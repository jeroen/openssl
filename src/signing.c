#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include "utils.h"

const EVP_MD* guess_hashfun(int length){
  switch(length){
  case 16:
    return EVP_md5();
  case 20:
    return EVP_sha1();
  case 32:
    return EVP_sha256();
  case 64:
    return EVP_sha512();
  }
  return EVP_md_null();
}

int gettype(const char *str){
  if (!strcmp(str, "md5")) {
    return NID_md5;
  } else if (!strcmp(str, "sha1")) {
    return NID_sha1;
  } else if (!strcmp(str, "sha256")) {
    return NID_sha256;
  }
  error("Invalid hash type: %s", str);
}

SEXP R_hash_sign(SEXP md, SEXP key){
  BIO *mem = BIO_new_mem_buf(RAW(key), LENGTH(key));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_sign_init(ctx) > 0);
  //bail(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) >= 0);
  bail(EVP_PKEY_CTX_set_signature_md(ctx, guess_hashfun(LENGTH(md))) > 0);

  //detemine buffer length (this is really required, over/under estimate can crash)
  size_t siglen;
  bail(EVP_PKEY_sign(ctx, NULL, &siglen, RAW(md), LENGTH(md)) > 0);

  //calculate signature
  unsigned char *sig = OPENSSL_malloc(siglen);
  bail(EVP_PKEY_sign(ctx, sig, &siglen, RAW(md), LENGTH(md)) > 0);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  SEXP res = allocVector(RAWSXP, siglen);
  memcpy(RAW(res), sig, siglen);
  OPENSSL_free(sig);
  return res;
}

SEXP R_hash_verify(SEXP md, SEXP sig, SEXP pubkey){
  const unsigned char *ptr = RAW(pubkey);
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &ptr, LENGTH(pubkey));
  bail(!!pkey);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_verify_init(ctx) > 0);
  //bail(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) >= 0);
  bail(EVP_PKEY_CTX_set_signature_md(ctx, guess_hashfun(LENGTH(md))) > 0);
  int res = EVP_PKEY_verify(ctx, RAW(sig), LENGTH(sig), RAW(md), LENGTH(md));
  bail(res >= 0);
  if(res == 0)
    error("Verification failed: incorrect signature");
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ScalarLogical(1);
}
