#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include "utils.h"
#include "compatibility.h"

/*
 * Adapted from example at: https://www.openssl.org/docs/crypto/EVP_DigestInit.html
 */

unsigned int digest_string(unsigned char *x, int len, SEXP key, const char *algo, unsigned char *md_value) {

  /* init openssl stuff */
  unsigned int md_len;
#ifdef HAS_OPENSSL3_API
  EVP_MD *md = EVP_MD_fetch(NULL, algo, NULL);
#else
  const EVP_MD *md = EVP_get_digestbyname(algo);
#endif

  if(!md)
    Rf_error("Unknown cryptographic algorithm %s\n", algo);

  if(key == R_NilValue){
    bail(EVP_Digest(x, len, md_value, &md_len, md, NULL));
  } else {
    bail(!!HMAC(md, RAW(key), LENGTH(key), x, len, md_value, &md_len));
  }
  return md_len;
}

SEXP R_digest_raw(SEXP x, SEXP algo, SEXP key){
  /* Check inputs */
  if(TYPEOF(x) != RAWSXP)
    Rf_error("Argument 'x' must be a raw vector.");

  /* Convert the Raw vector to an unsigned char */
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len = digest_string(RAW(x), Rf_length(x), key, CHAR(Rf_asChar(algo)), md_value);

  /* create raw output vector */
  SEXP out = PROTECT(Rf_allocVector(RAWSXP, md_len));
  memcpy(RAW(out), md_value, md_len);
  UNPROTECT(1);
  return out;
}

SEXP R_digest(SEXP x, SEXP algo, SEXP key){
  if(!Rf_isString(x))
    Rf_error("Argument 'x' must be a character vector.");
  if(!Rf_isString(algo))
    Rf_error("Argument 'algo' must be a character vector.");

  int len = Rf_length(x);
  SEXP out = PROTECT(Rf_allocVector(STRSXP, len));
  for (int i = 0; i < len; i++) {
    /* check for NA */
    if(STRING_ELT(x, i) == NA_STRING) {
      SET_STRING_ELT(out, i, NA_STRING);
      continue;
    }
    /* create hash */
    const char* str = CHAR(STRING_ELT(x, i));
    int stringlen = LENGTH(STRING_ELT(x, i));
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = digest_string( (unsigned char*) str, stringlen, key, CHAR(Rf_asChar(algo)), md_value);

    /* create character vector */
    char strbuf[2*md_len+1];
    for (int i = 0; i < md_len; i++) {
      snprintf(strbuf + i*2, 3, "%02x", (unsigned int) md_value[i]);
    }
    SET_STRING_ELT(out, i, Rf_mkChar(strbuf));
  }
  UNPROTECT(1);
  return out;
}
