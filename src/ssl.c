#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <unistd.h>

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

SEXP R_download_cert(SEXP hostname, SEXP portnum) {
  /* grab inputs */
  int port = asInteger(portnum);
  struct sockaddr_in dest_addr;
  struct hostent *host = gethostbyname(CHAR(STRING_ELT(hostname, 0)));
  if(!host)
    error("Failed to resolve hostname");

  /* create TCP socket */
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
  memset(&(dest_addr.sin_zero), '\0', 8);

  /* Connect */
  char *tmp_ptr = inet_ntoa(dest_addr.sin_addr);
  if (connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) < 0)
    error("Failed to connect to %s on port %d", tmp_ptr, port);

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
