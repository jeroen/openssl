#include <Rinternals.h>
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include "compatibility.h"

#include <openssl/evp.h>
#ifdef EVP_PKEY_ED25519
#define HAS_ECX
#endif

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#include <openssl/provider.h>
#endif

SEXP R_openssl_config(void) {
  int has_ec = 1;
  #ifdef OPENSSL_NO_EC
  has_ec = 0;
  #endif
  int has_x25519 = 0;
  #ifdef HAS_ECX
  has_x25519 = 1;
  #endif
  int has_fips = 0;
  #ifdef OPENSSL_FIPS
  has_fips = 1;
  #endif
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 4));
#ifdef HAS_OPENSSL11_API
  SET_VECTOR_ELT(res, 0, Rf_mkString(OpenSSL_version(OPENSSL_VERSION)));
#else
  SET_VECTOR_ELT(res, 0, Rf_mkString(OPENSSL_VERSION_TEXT));
#endif
  SET_VECTOR_ELT(res, 1, Rf_ScalarLogical(has_ec));
  SET_VECTOR_ELT(res, 2, Rf_ScalarLogical(has_x25519));
  SET_VECTOR_ELT(res, 3, Rf_ScalarLogical(has_fips));
  UNPROTECT(1);
  return res;
}

SEXP R_openssl_fips_mode(void){
#ifdef LIBRESSL_VERSION_NUMBER
  int enabled = 0;
#elif OPENSSL_VERSION_MAJOR < 3
  int enabled = FIPS_mode();
#else
  int enabled = EVP_default_properties_is_fips_enabled(NULL);
  if (!enabled) {
    enabled = OSSL_PROVIDER_available(NULL, "fips") &&
      !OSSL_PROVIDER_available(NULL, "default");
  }
#endif
  return Rf_ScalarLogical(enabled);
}
