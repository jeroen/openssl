#include <Rinternals.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>

SEXP R_openssl_config() {
  int has_ec = 1;
  #ifdef OPENSSL_NO_EC
  has_ec = 0;
  #endif
  SEXP res = PROTECT(allocVector(VECSXP, 2));
  SET_VECTOR_ELT(res, 0, mkString(OPENSSL_VERSION_TEXT));
  SET_VECTOR_ELT(res, 1, ScalarLogical(has_ec));
  UNPROTECT(1);
  return res;
}
