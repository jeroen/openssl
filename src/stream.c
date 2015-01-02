#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include <openssl/evp.h>

void fin_md(SEXP ptr){
  if(!R_ExternalPtrAddr(ptr)) return;
  EVP_MD_CTX_destroy(R_ExternalPtrAddr(ptr));
  R_ClearExternalPtr(ptr);
}

SEXP R_md_init(SEXP algo){
  const EVP_MD *md = EVP_get_digestbyname(CHAR(asChar(algo)));
  if(!md)
    error("Unknown cryptographic algorithm %s\n", CHAR(asChar(algo)));
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  SEXP ptr = PROTECT(R_MakeExternalPtr(mdctx, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(ptr, fin_md, 1);
  setAttrib(ptr, R_ClassSymbol, mkString("md"));
  UNPROTECT(1);
  return ptr;
}

SEXP R_md_feed(SEXP md, SEXP data){
  EVP_MD_CTX *mdctx = R_ExternalPtrAddr(md);
  if(!mdctx)
    error("mdctx is null");
  EVP_DigestUpdate(mdctx, RAW(data), length(data));
  return ScalarLogical(1);
}

SEXP R_md_final(SEXP md){
  if(!R_ExternalPtrAddr(md))
    error("md is null");

  /* Calculates the hash */
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  EVP_DigestFinal_ex(R_ExternalPtrAddr(md), (unsigned char *) &md_value, &md_len);

  /* create output raw vec */
  SEXP out = PROTECT(allocVector(RAWSXP, md_len));
  memcpy(RAW(out), md_value, md_len);
  UNPROTECT(1);
  return out;
}
