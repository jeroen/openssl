//getaddrinfo is an extension (not C99)
#if !defined(_WIN32) && !defined(__sun) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

//needed to expose inet_ntop
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
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
#include "compatibility.h"

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

int pending_interrupt(void) {
  return !(R_ToplevelExec(check_interrupt_fn, NULL));
}

static SEXP R_write_cert(X509 *cert){
  unsigned char *buf = NULL;
  int len = i2d_X509(cert, &buf);
  SEXP out = PROTECT(allocVector(RAWSXP, len));
  memcpy(RAW(out), buf, len);
  setAttrib(out, R_ClassSymbol, mkString("cert"));
  OPENSSL_free(buf);
  UNPROTECT(1);
  return out;
}

static SEXP R_write_cert_chain(STACK_OF(X509) *chain){
  int n = sk_X509_num(chain);
  bail(n >= 0);
  SEXP res = PROTECT(allocVector(VECSXP, n));
  for(int i = 0; i < n; i++){
    SET_VECTOR_ELT(res, i, R_write_cert(sk_X509_value(chain, i)));
  }
  UNPROTECT(1);
  return res;
}

SEXP R_download_cert(SEXP hostname, SEXP service, SEXP ipv4_only) {
#ifdef __EMSCRIPTEN__
  Rf_error("Raw network access is unavailable when running under Wasm.");
  return NULL;
#else
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
  SEXP res = R_write_cert_chain(SSL_get_peer_cert_chain(ssl));

  /* Cleanup SSL */
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  return res;
#endif // __EMSCRIPTEN__
}

static int sslVerifyCallback(X509_STORE_CTX* x509Ctx, void *fun) {
  X509 *cert = MY_X509_STORE_CTX_get0_cert(x509Ctx);
  if(!cert){
    REprintf("Did not get certificate from the server\n");
    return 0;
  }
  SEXP p1 = PROTECT(R_write_cert(cert));
  SEXP call = PROTECT(Rf_lang2(fun, p1));
  int err = 0;
  SEXP res = PROTECT(R_tryEval(call, R_GlobalEnv, &err));
  if (err || TYPEOF(res) != LGLSXP || length(res) != 1) {
    UNPROTECT(3);
    REprintf("sslVerifyCallback must return TRUE (continue) or FALSE (stop)");
    return 0;
  }
  UNPROTECT(3);
  return Rf_asLogical(res);
}

SEXP R_ssl_ctx_set_verify_callback(SEXP ptr, SEXP fun){
  if(TYPEOF(ptr) != EXTPTRSXP || !Rf_inherits(ptr, "ssl_ctx"))
    Rf_error("Object is not a ssl_ctx");
  if(!Rf_isFunction(fun))
    Rf_error("Callback is not a function");
  SSL_CTX *ctx = R_ExternalPtrAddr(ptr);
  if(ctx == NULL)
    return R_NilValue;
  R_SetExternalPtrProtected(ptr, fun);
  SSL_CTX_set_cert_verify_callback(ctx, sslVerifyCallback, fun);
  return Rf_ScalarInteger(1);
}

SEXP R_ssl_ctx_add_cert_to_store(SEXP ssl_ctx, SEXP cert){
  if(TYPEOF(ssl_ctx) != EXTPTRSXP || !Rf_inherits(ssl_ctx, "ssl_ctx"))
    Rf_error("Object is not a ssl_ctx");
  if(!inherits(cert, "cert"))
    Rf_error("cert is not a cert object");
  const unsigned char *certptr = RAW(cert);
  X509 *crt = d2i_X509(NULL, &certptr, Rf_length(cert));
  bail(!!crt);
  SSL_CTX *ctx = R_ExternalPtrAddr(ssl_ctx);
  if(ctx == NULL)
    return R_NilValue;
  X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), crt);
  X509_free(crt);
  return Rf_ScalarInteger(1);
}
