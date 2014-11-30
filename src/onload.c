#include <Rinternals.h>
#include "apple.h"
#include <openssl/evp.h>

SEXP R_openssl_init(){
  OpenSSL_add_all_digests();
  return R_NilValue;
}

SEXP R_openssl_cleanup(){
  EVP_cleanup();
  return R_NilValue;
}

