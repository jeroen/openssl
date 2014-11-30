#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include <openssl/evp.h>

/*
 * Adapted from example at: https://www.openssl.org/docs/crypto/EVP_DigestInit.html
 */

SEXP digest_string(const char *x, const char *algo, int string){

  /* init openssl stuff */
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  const EVP_MD *md = EVP_get_digestbyname(algo);
  if(!md)
    error("Unknown message digest %s\n", algo);
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

  /* generate hash */
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, x, strlen(x));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

  /* create outputs */
  SEXP out;
  if(string){
    char mdString[2*md_len+1];
    for (int i = 0; i < md_len; i++) {
      sprintf(&mdString[i*2], "%02x", (unsigned int) md_value[i]);
    }
    mdString[2*md_len+1] = '\0';
    out = PROTECT(mkChar(mdString));
  } else {
    out = PROTECT(allocVector(RAWSXP, md_len));
    for (int i = 0; i < md_len; i++) {
      RAW(out)[i] = md_value[i];
    }
  }

  /* finish up */
  UNPROTECT(1);
  return out;
}

SEXP R_digest_raw(SEXP x, SEXP algo){
  /* Check inputs */
  if(!isString(x))
    error("Argument 'x' must be a character vector.");

  return digest_string(CHAR(asChar(x)), CHAR(asChar(algo)), 0);
}

SEXP R_digest(SEXP x, SEXP algo){
  if(!isString(x))
    error("Argument 'x' must be a character vector.");
  if(!isString(algo))
    error("Argument 'algo' must be a character vector.");

  int len = length(x);
  const char* alg = CHAR(asChar(algo));
  SEXP out = PROTECT(allocVector(STRSXP, len));
  for (int i = 0; i < len; i++) {
    SET_STRING_ELT(out, i, digest_string(CHAR(STRING_ELT(x, i)), alg, 1));
  }
  UNPROTECT(1);
  return out;
}

SEXP R_openssl_init(){
  OpenSSL_add_all_digests();
  return R_NilValue;
}

SEXP R_openssl_cleanup(){
  EVP_cleanup();
  return R_NilValue;
}
