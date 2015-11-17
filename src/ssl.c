#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <unistd.h>
#include <fcntl.h>

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

  // Set non-blocking
#ifndef _WIN32
  long arg = fcntl(sockfd, F_GETFL, NULL);
  arg |= O_NONBLOCK;
  fcntl(sockfd, F_SETFL, arg);
#endif

  /* Connect */
  struct timeval tv;
  fd_set myset;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  FD_ZERO(&myset);
  FD_SET(sockfd, &myset);
  int elapsed_time = 0;
  if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) < 0){
    //for blocking sockets:
    //error("Failed to connect to %s on port %d", inet_ntoa(dest_addr.sin_addr), port);
    while(select(sockfd+1, NULL, &myset, NULL, &tv) < 1){
      // wait for 10 sec or user interruption
      if(pending_interrupt() || ++elapsed_time > 9){
        close(sockfd);
        if(elapsed_time > 9)
          error("Connect timeout");
        return R_NilValue;
      }
    }
  }

#ifndef _WIN32
  /* Set back to blocking mode */
  arg = fcntl(sockfd, F_GETFL, NULL);
  arg &= (~O_NONBLOCK);
  fcntl(sockfd, F_SETFL, arg);
#endif

  /* Setup SSL */
  SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
  bail(!!ctx);
  SSL *ssl = SSL_new(ctx);
  bail(!!ssl);

  /* Required for SNI (e.g. cloudflare) */
  bail(SSL_set_tlsext_host_name(ssl, CHAR(STRING_ELT(hostname, 0))));

  /* Retrieve cert */
  SSL_set_fd(ssl, sockfd);
  bail(SSL_connect(ssl));

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

  /* Cleanup connection */
  SSL_free(ssl);
  close(sockfd);
  SSL_CTX_free(ctx);

  /* Test for cert */
  if(n < 1)
    error("Server did not present a certificate");

  UNPROTECT(1);
  return res;
}
