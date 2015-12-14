#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#include <openssl/ssl.h>
#include "utils.h"

void check_interrupt_fn(void *dummy) {
  R_CheckUserInterrupt();
}

int pending_interrupt() {
  return !(R_ToplevelExec(check_interrupt_fn, NULL));
}

SEXP R_download_cert(SEXP hostname, SEXP portnum) {
  /* resolve hostname */
  struct hostent *host = gethostbyname(CHAR(STRING_ELT(hostname, 0)));
  if(!host)
    error("Failed to resolve hostname");

  /* create TCP socket */
  int port = asInteger(portnum);
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in dest_addr;
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  memcpy(&dest_addr.sin_addr, host->h_addr, host->h_length);
  memset(&(dest_addr.sin_zero), '\0', sizeof(dest_addr.sin_zero));

  /* Set to non-blocking mode */
#ifdef _WIN32
  u_long nonblocking = 1;
  ioctlsocket(sockfd, FIONBIO, &nonblocking);
#define NONBLOCK_OK (WSAGetLastError() == WSAEWOULDBLOCK)
#else
  long arg = fcntl(sockfd, F_GETFL, NULL);
  arg |= O_NONBLOCK;
  fcntl(sockfd, F_SETFL, arg);
#define NONBLOCK_OK (errno == EINPROGRESS)
#endif

  /* Connect */
  struct timeval tv;
  fd_set myset;
  tv.tv_sec = 5; // 5 sec timeout
  tv.tv_usec = 0;
  FD_ZERO(&myset);
  FD_SET(sockfd, &myset);

  /* Try to connect */
  connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr));
  if(!NONBLOCK_OK || select(FD_SETSIZE, NULL, &myset, NULL, &tv) < 1){
    close(sockfd);
    error("Failed to connect to %s on port %d", inet_ntoa(dest_addr.sin_addr), port);
  }

  /* Set back in blocking mode */
#ifdef _WIN32
  nonblocking = 0;
  ioctlsocket(sockfd, FIONBIO, &nonblocking);
#else
  arg = fcntl(sockfd, F_GETFL, NULL);
  arg &= (~O_NONBLOCK);
  fcntl(sockfd, F_SETFL, arg);
#endif

  int err = 0;
  socklen_t errbuf = sizeof (err);
  if(getsockopt (sockfd, SOL_SOCKET, SO_ERROR, (char*) &err, &errbuf) || err){
    close(sockfd);
    error("Failed to connect to %s on port %d", inet_ntoa(dest_addr.sin_addr), port);
  }

  /* Setup SSL */
  SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
  bail(!!ctx);
  SSL *ssl = SSL_new(ctx);
  bail(!!ssl);

  /* Required for SNI (e.g. cloudflare) */
  bail(SSL_set_tlsext_host_name(ssl, CHAR(STRING_ELT(hostname, 0))));

  /* SSL handshake to get cert */
  SSL_set_fd(ssl, sockfd);
  int con = SSL_connect(ssl);
  close(sockfd);
  bail(con > 0);

  /* Convert certs to RAW. Not sure if I should free these */
  STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
  int n = sk_X509_num(chain);
  bail(n > 0);

  int len;
  unsigned char *buf = NULL;
  SEXP res = PROTECT(allocVector(VECSXP, n));
  for(int i = 0; i < n; i++){
    len = i2d_X509(sk_X509_value(chain, i), &buf);
    SET_VECTOR_ELT(res, i, allocVector(RAWSXP, len));
    memcpy(RAW(VECTOR_ELT(res, i)), buf, len);
    setAttrib(VECTOR_ELT(res, i), R_ClassSymbol, mkString("cert"));
    free(buf);
    buf = NULL;
  }

  /* Cleanup SSL */
  SSL_free(ssl);
  SSL_CTX_free(ctx);

  /* Test for cert */
  if(n < 1)
    error("Server did not present a certificate");

  UNPROTECT(1);
  return res;
}
