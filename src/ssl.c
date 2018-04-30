//getaddrinfo is an extension (not C99)
#if !defined(_WIN32) && !defined(__sun) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

//see https://github.com/jeroen/openssl/issues/41
#if defined(__FreeBSD__) && !defined(__BSD_VISIBLE)
#define __BSD_VISIBLE 1
#endif

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
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include "utils.h"

#ifdef _WIN32
#define NONBLOCK_OK (WSAGetLastError() == WSAEWOULDBLOCK)
void set_nonblocking(int sockfd){
  u_long nonblocking = 1;
  ioctlsocket(sockfd, FIONBIO, &nonblocking);
}

void set_blocking(int sockfd){
  u_long nonblocking = 0;
  ioctlsocket(sockfd, FIONBIO, &nonblocking);
}

const char *formatError(DWORD res){
  static char buf[1000], *p;
  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, res,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                buf, 1000, NULL);
  p = buf+strlen(buf) -1;
  if(*p == '\n') *p = '\0';
  p = buf+strlen(buf) -1;
  if(*p == '\r') *p = '\0';
  p = buf+strlen(buf) -1;
  if(*p == '.') *p = '\0';
  return buf;
}
#define getsyserror() formatError(GetLastError())
#else
#define NONBLOCK_OK (errno == EINPROGRESS)
void set_nonblocking(int sockfd){
  long arg = fcntl(sockfd, F_GETFL, NULL);
  arg |= O_NONBLOCK;
  fcntl(sockfd, F_SETFL, arg);
}
void set_blocking(int sockfd){
  long arg = fcntl(sockfd, F_GETFL, NULL);
  arg &= ~O_NONBLOCK;
  fcntl(sockfd, F_SETFL, arg);
}
#define getsyserror() strerror(errno)
#endif

void check_interrupt_fn(void *dummy) {
  R_CheckUserInterrupt();
}

int pending_interrupt() {
  return !(R_ToplevelExec(check_interrupt_fn, NULL));
}

SEXP R_download_cert(SEXP hostname, SEXP service, SEXP ipv4_only) {
  /* The 'hints' arg is only needed for solaris */
  struct addrinfo hints;
  memset(&hints,0,sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = asLogical(ipv4_only) ? AF_INET : PF_UNSPEC;

  /* Because gethostbyname() is deprecated */
  struct addrinfo *addr;
  if(getaddrinfo(CHAR(STRING_ELT(hostname, 0)), CHAR(STRING_ELT(service, 0)), &hints, &addr))
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

  /* Connect data*/
  struct timeval tv;
  fd_set writefds;
  tv.tv_sec = 5; // 5 sec timeout
  tv.tv_usec = 0;
  FD_ZERO(&writefds);
  FD_SET(sockfd, &writefds);

  /* Try to connect, but don't block forever */
  set_nonblocking(sockfd);
  int err = connect(sockfd, addr->ai_addr, (int)addr->ai_addrlen);
  int in_progress = NONBLOCK_OK;
  set_blocking(sockfd);
  freeaddrinfo(addr);

  /* Non-zero can either mean error or non-block in-progress */
  if(err < 0){
    if(in_progress){
      int ready = select(sockfd + 1, NULL, &writefds, NULL, &tv);
      if(ready < 1 || !FD_ISSET(sockfd, &writefds)){
        close(sockfd);
        Rf_error("Failed to connect to %s on port %d (%s)", ip, port, ready ? getsyserror() : "Timeout reached");
      }
    } else {
      close(sockfd);
      Rf_error("Failed to connect to %s on port %d (%s)", ip, port, getsyserror());
    }
  }

  /* test connection is ready */
  socklen_t errbuf = sizeof (err);
  if(getsockopt (sockfd, SOL_SOCKET, SO_ERROR, (char*) &err, &errbuf) || err){
    close(sockfd);
    Rf_error("Failed to connect to %s on port %d", ip, port);
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
  if(con != 1){
    switch(SSL_get_error(ssl, con)){
    case SSL_ERROR_SYSCALL:
      Rf_error("Failure to perform TLS handshake: %s", strerror(errno));
      break;
    default:
      raise_error();
    }
  }

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
    OPENSSL_free(buf);
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
