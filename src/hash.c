#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <openssl/evp.h>

/*
 * Adapted from example at: https://www.openssl.org/docs/crypto/EVP_DigestInit.html
 */

unsigned int digest_string(const char *x, const char *algo, int len, unsigned char *md_value) {

  /* init openssl stuff */
  unsigned int md_len;
  const EVP_MD *md = EVP_get_digestbyname(algo);
  if(!md)
    error("Unknown cryptographic algorithm %s\n", algo);
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

  /* generate hash */
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, x, len);
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);
  return md_len;
}

SEXP R_digest_raw(SEXP x, SEXP algo){
  /* Check inputs */
  if(TYPEOF(x) != RAWSXP)
    error("Argument 'x' must be a raw vector.");

  /* Convert the Raw vector to an unsigned char */
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len = digest_string((const char*) RAW(x), CHAR(asChar(algo)), length(x), md_value);

  /* create raw output vector */
  SEXP out = PROTECT(allocVector(RAWSXP, md_len));
  memcpy(RAW(out), md_value, md_len);
  UNPROTECT(1);
  return out;
}

SEXP R_digest(SEXP x, SEXP algo){
  if(!isString(x))
    error("Argument 'x' must be a character vector.");
  if(!isString(algo))
    error("Argument 'algo' must be a character vector.");

  int len = length(x);
  SEXP out = PROTECT(allocVector(STRSXP, len));
  for (int i = 0; i < len; i++) {
    /* check for NA */
    if(STRING_ELT(x, i) == NA_STRING) {
      SET_STRING_ELT(out, i, NA_STRING);
      continue;
    }
    /* create hash */
    const char* str = CHAR(STRING_ELT(x, i));
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len = digest_string(str, CHAR(asChar(algo)), strlen(str), md_value);

    /* create character vector */
    char mdString[2*md_len+1];
    for (int i = 0; i < md_len; i++) {
      sprintf(&mdString[i*2], "%02x", (unsigned int) md_value[i]);
    }
    mdString[2*md_len] = '\0';
    SET_STRING_ELT(out, i, mkChar(mdString));
  }
  UNPROTECT(1);
  return out;
}
