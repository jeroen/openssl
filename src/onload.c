#include <Rinternals.h>
#include "apple.h"
#include <openssl/evp.h>
#include <openssl/err.h>

SEXP R_openssl_init(){
  OpenSSL_add_all_digests();
  ERR_load_crypto_strings();
  return R_NilValue;
}

SEXP R_openssl_cleanup(){
  ERR_free_strings();
  EVP_cleanup();
  return R_NilValue;
}
