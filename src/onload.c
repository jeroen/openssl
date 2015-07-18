#include "apple.h"
#include <R_ext/Rdynload.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void R_init_openssl(DllInfo *info) {
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();
}

void R_unload_curl(DllInfo *info) {
  ERR_free_strings();
  EVP_cleanup();
}
