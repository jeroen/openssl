#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include <openssl/evp.h>

/*
 * Adapted from example at: https://www.openssl.org/docs/crypto/EVP_DigestInit.html
 */

SEXP R_digest_string(SEXP x, SEXP algo){
  /* Check inputs */
  if(!isString(x))
    error("Argument 'object' must be a character vector.");

  /* init openssl stuff */
  OpenSSL_add_all_digests();
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  const EVP_MD *md = EVP_get_digestbyname(CHAR(asChar(algo)));
  if(!md)
    error("Unknown message digest %s\n", CHAR(asChar(algo)));
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();

  // generate hash
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, CHAR(asChar(x)), strlen(CHAR(asChar(x))));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_destroy(mdctx);

  /* create outputs */
  SEXP out = PROTECT(allocVector(RAWSXP, md_len));
  for (int i = 0; i < md_len; i++) {
    RAW(out)[i] = md_value[i];
  }

  /* finish up */
  EVP_cleanup();
  UNPROTECT(1);
  return out;
}
