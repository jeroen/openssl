#include <R_ext/Rdynload.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include "compatibility.h"

#ifdef HAS_OPENSSL3_API
#include <openssl/provider.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#endif

void R_init_openssl(DllInfo *info) {
  R_registerRoutines(info, NULL, NULL, NULL, NULL);
  R_useDynamicSymbols(info, TRUE);
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
#ifdef HAS_OPENSSL3_API
  OSSL_PROVIDER_load(NULL, "legacy");
  OSSL_PROVIDER_load(NULL, "default");
#endif
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();
}
