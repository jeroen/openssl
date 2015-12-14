#include <R_ext/Rdynload.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>

void R_init_openssl(DllInfo *info) {
#ifdef _WIN32
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
  OpenSSL_add_all_digests();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();
}

void R_unload_curl(DllInfo *info) {
  ERR_free_strings();
  EVP_cleanup();
}
