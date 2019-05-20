#include <Rinternals.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include "compatibility.h"

SEXP R_openssl_config() {
  int has_ec = 1;
  int has_openssl11 = 0;
  #ifdef OPENSSL_NO_EC
  has_ec = 0;
  #endif
  #ifdef HAS_OPENSSL11_API
  has_openssl11 = 1;
  #endif
  SEXP res = PROTECT(allocVector(VECSXP, 3));
  SET_VECTOR_ELT(res, 0, mkString(OPENSSL_VERSION_TEXT));
  SET_VECTOR_ELT(res, 1, ScalarLogical(has_ec));
  SET_VECTOR_ELT(res, 2, ScalarLogical(has_openssl11));
  UNPROTECT(1);
  return res;
}
