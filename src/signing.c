#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <openssl/pem.h>

SEXP R_sign_sha256(SEXP md, SEXP key){
  BIO *mem = BIO_new_mem_buf(RAW(key), LENGTH(key));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_sign_init(ctx) >= 0);
  //bail(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) >= 0);
  bail(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) >= 0);
  size_t siglen;
  unsigned char buf[10000];
  bail(EVP_PKEY_sign(ctx, buf, &siglen, RAW(md), LENGTH(md)) >= 0);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  SEXP res = allocVector(RAWSXP, siglen);
  memcpy(RAW(res), buf, siglen);
  return res;
}

SEXP R_verify_sha256(SEXP md, SEXP sig, SEXP pubkey){
  const unsigned char *ptr = RAW(pubkey);
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &ptr, LENGTH(pubkey));
  bail(!!pkey);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_verify_init(ctx) >= 0);
  //bail(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) >= 0);
  bail(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) >= 0);
  int res = EVP_PKEY_verify(ctx, RAW(sig), LENGTH(sig), RAW(md), LENGTH(md));
  bail(res >= 0);
  if(res == 0)
    error("Verification failed: incorrect signature");
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ScalarLogical(1);
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

SEXP R_rsa_sign(SEXP hashdata, SEXP type, SEXP keydata){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(keydata);
  bail(!!d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(keydata)));
  unsigned char* buf[RSA_size(rsa)];
  unsigned int len;
  int hashtype = gettype(CHAR(STRING_ELT(type, 0)));
  bail(!!RSA_sign(hashtype, RAW(hashdata), LENGTH(hashdata), (unsigned char *) buf, &len, rsa));
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  return res;
}

SEXP R_rsa_verify(SEXP hashdata, SEXP sigdata, SEXP type, SEXP keydata){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(keydata);
  bail(!!d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(keydata)));
  int hashtype = gettype(CHAR(STRING_ELT(type, 0)));
  bail(!!RSA_verify(hashtype, RAW(hashdata), LENGTH(hashdata), RAW(sigdata), LENGTH(sigdata), rsa));
  return ScalarLogical(1);
}
