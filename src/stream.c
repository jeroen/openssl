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
#ifdef HAS_OPENSSL3_API
  EVP_MD *md = EVP_MD_fetch(NULL, CHAR(Rf_asChar(algo)), NULL);
#else
  const EVP_MD *md = EVP_get_digestbyname(CHAR(Rf_asChar(algo)));
#endif
  if(!md)
    Rf_error("Unknown cryptographic algorithm %s\n", CHAR(Rf_asChar(algo)));
  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, md, NULL);
  SEXP ptr = PROTECT(R_MakeExternalPtr(mdctx, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(ptr, fin_md, TRUE);
  Rf_setAttrib(ptr, R_ClassSymbol, Rf_mkString("md"));
  UNPROTECT(1);
  return ptr;
}

SEXP R_md_feed(SEXP md, SEXP data){
  EVP_MD_CTX *mdctx = R_ExternalPtrAddr(md);
  if(!mdctx)
    Rf_error("mdctx is null");
  EVP_DigestUpdate(mdctx, RAW(data), Rf_length(data));
  return Rf_ScalarLogical(1);
}

SEXP R_md_final(SEXP md){
  if(!R_ExternalPtrAddr(md))
    Rf_error("md is null");

  /* Calculates the hash */
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  EVP_DigestFinal_ex(R_ExternalPtrAddr(md), (unsigned char *) &md_value, &md_len);

  /* create output raw vec */
  SEXP out = Rf_allocVector(RAWSXP, md_len);
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
#ifdef HAS_OPENSSL3_API
  EVP_MD *md = EVP_MD_fetch(NULL, CHAR(Rf_asChar(algo)), NULL);
#else
  const EVP_MD *md = EVP_get_digestbyname(CHAR(Rf_asChar(algo)));
#endif
  if(!md)
    Rf_error("Unknown cryptographic algorithm %s\n", CHAR(Rf_asChar(algo)));
#ifdef HAS_OPENSSL11_API
  HMAC_CTX* ctx = HMAC_CTX_new();
#else
  HMAC_CTX* ctx = malloc(sizeof(HMAC_CTX));
  HMAC_CTX_init(ctx);
#endif
  bail(HMAC_Init_ex(ctx, RAW(key), LENGTH(key), md, NULL));
  SEXP ptr = PROTECT(R_MakeExternalPtr(ctx, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(ptr, fin_hmac, TRUE);
  Rf_setAttrib(ptr, R_ClassSymbol, Rf_mkString("md"));
  UNPROTECT(1);
  return ptr;
}

SEXP R_hmac_feed(SEXP ptr, SEXP data){
  HMAC_CTX *ctx = R_ExternalPtrAddr(ptr);
  if(!ctx)
    Rf_error("ctx is null");
  bail(HMAC_Update(ctx, RAW(data), LENGTH(data)));
  return Rf_ScalarLogical(1);
}

SEXP R_hmac_final(SEXP ptr){
  HMAC_CTX *ctx = R_ExternalPtrAddr(ptr);
  if(!ctx)
    Rf_error("ctx is null");

  /* Calculates the hash */
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  bail(HMAC_Final(ctx, (unsigned char *) &md_value, &md_len));

  /* create output raw vec */
  SEXP out = PROTECT(Rf_allocVector(RAWSXP, md_len));
  memcpy(RAW(out), md_value, md_len);
  UNPROTECT(1);
  return out;
}
