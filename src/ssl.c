#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
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

SEXP R_download_cert(SEXP hostname, SEXP service) {
  /* Because gethostbyname() is deprecated */
  struct addrinfo *addr;
  if(getaddrinfo(CHAR(STRING_ELT(hostname, 0)), CHAR(STRING_ELT(service, 0)), 0, &addr))
    error("Failed to resolve hostname or unknown port");
  int sockfd = socket(addr->ai_family, SOCK_STREAM, 0);

  /* For debugging */
  struct sockaddr *sa = addr->ai_addr;

  /* IPv4 vs v6 */
  int port = 0;
  char ip[INET6_ADDRSTRLEN];
  if (sa->sa_family == AF_INET) {
    struct sockaddr_in *sa_in = (struct sockaddr_in*) sa;
    port = ntohs(sa_in->sin_port);
    inet_ntop(AF_INET, &(sa_in->sin_addr), ip, INET_ADDRSTRLEN);
  } else {
    struct sockaddr_in6 *sa_in = (struct sockaddr_in6*) sa;
    port = ntohs(sa_in->sin6_port);
    inet_ntop(AF_INET6, &(sa_in->sin6_addr), ip, INET6_ADDRSTRLEN);
  }

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
  connect(sockfd, addr->ai_addr, (int)addr->ai_addrlen);
  if(!NONBLOCK_OK || select(FD_SETSIZE, NULL, &myset, NULL, &tv) < 1){
    close(sockfd);
    error("Failed to connect to %s on port %d", ip, port);
  }
  freeaddrinfo(addr);

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
    error("Failed to connect to %s on port %d", ip, port);
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
