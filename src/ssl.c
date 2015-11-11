#include <Rinternals.h>
#include "apple.h"
#include "utils.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
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
  X509 *cert = SSL_get_peer_certificate(ssl);
  if(!cert)
    error("Server did not present a certificate");

  /* Cleanup */
  SSL_free(ssl);
  close(sockfd);
  SSL_CTX_free(ctx);

  //output
  unsigned char *buf = NULL;
  int len = i2d_X509(cert, &buf);
  bail(len > 0);
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  setAttrib(res, R_ClassSymbol, mkString("cert"));
  memcpy(RAW(res), buf, len);
  UNPROTECT(1);
  free(buf);
  return res;
}
