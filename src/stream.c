#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include "utils.h"
#include "compatibility.h"

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
  R_RegisterCFinalizerEx(ptr, fin_md, TRUE);
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
  SEXP out = allocVector(RAWSXP, md_len);
  memcpy(RAW(out), md_value, md_len);
  return out;
}

void fin_hmac(SEXP ptr){
  if(!R_ExternalPtrAddr(ptr)) return;
#ifdef HAS_OPENSSL11_API
  HMAC_CTX_free(R_ExternalPtrAddr(ptr));
#else
  HMAC_CTX_cleanup(R_ExternalPtrAddr(ptr));
  free(R_ExternalPtrAddr(ptr));
#endif
  R_ClearExternalPtr(ptr);
}

SEXP R_hmac_init(SEXP algo, SEXP key){
  const EVP_MD *md = EVP_get_digestbyname(CHAR(asChar(algo)));
  if(!md)
    error("Unknown cryptographic algorithm %s\n", CHAR(asChar(algo)));
#ifdef HAS_OPENSSL11_API
  HMAC_CTX* ctx = HMAC_CTX_new();
#else
  HMAC_CTX* ctx = malloc(sizeof(HMAC_CTX));
  HMAC_CTX_init(ctx);
#endif
  bail(HMAC_Init_ex(ctx, RAW(key), LENGTH(key), md, NULL));
  SEXP ptr = PROTECT(R_MakeExternalPtr(ctx, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(ptr, fin_hmac, TRUE);
  setAttrib(ptr, R_ClassSymbol, mkString("md"));
  UNPROTECT(1);
  return ptr;
}

SEXP R_hmac_feed(SEXP ptr, SEXP data){
  HMAC_CTX *ctx = R_ExternalPtrAddr(ptr);
  if(!ctx)
    error("ctx is null");
  bail(HMAC_Update(ctx, RAW(data), LENGTH(data)));
  return ScalarLogical(1);
}

SEXP R_hmac_final(SEXP ptr){
  HMAC_CTX *ctx = R_ExternalPtrAddr(ptr);
  if(!ctx)
    error("ctx is null");

  /* Calculates the hash */
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  bail(HMAC_Final(ctx, (unsigned char *) &md_value, &md_len));

  /* create output raw vec */
  SEXP out = PROTECT(allocVector(RAWSXP, md_len));
  memcpy(RAW(out), md_value, md_len);
  UNPROTECT(1);
  return out;
}
