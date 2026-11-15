#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "utils.h"

static void set_rsa_padding(EVP_PKEY_CTX *ctx, SEXP oaep, SEXP md){
  bail(EVP_PKEY_CTX_set_rsa_padding(ctx, Rf_asLogical(oaep) ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING) > 0);
  if(Rf_asLogical(oaep) && Rf_length(md)){
    const EVP_MD *digest = EVP_get_digestbyname(CHAR(STRING_ELT(md, 0)));
    if(!digest)
      Rf_error("Invalid hash: %s", CHAR(STRING_ELT(md, 0)));
    bail(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, digest) > 0);
    bail(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, digest) > 0);
  }
}

SEXP R_rsa_encrypt(SEXP data, SEXP keydata, SEXP oaep, SEXP md) {
  const unsigned char *ptr = RAW(keydata);
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &ptr, LENGTH(keydata));
  bail(!!pkey);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  EVP_PKEY_free(pkey);
  bail(!!ctx);
  bail(EVP_PKEY_encrypt_init(ctx) > 0);
  set_rsa_padding(ctx, oaep, md);
  size_t len = 0;
  bail(EVP_PKEY_encrypt(ctx, NULL, &len, RAW(data), LENGTH(data)) > 0);
  unsigned char *buf = OPENSSL_malloc(len);
  int ok = EVP_PKEY_encrypt(ctx, buf, &len, RAW(data), LENGTH(data)) > 0;
  EVP_PKEY_CTX_free(ctx);
  if(!ok){
    OPENSSL_free(buf);
    bail(0);
  }
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_rsa_decrypt(SEXP data, SEXP keydata, SEXP oaep, SEXP md){
  BIO *mem = BIO_new_mem_buf(RAW(keydata), LENGTH(keydata));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  EVP_PKEY_free(pkey);
  bail(!!ctx);
  bail(EVP_PKEY_decrypt_init(ctx) > 0);
  set_rsa_padding(ctx, oaep, md);
  size_t len = 0;
  bail(EVP_PKEY_decrypt(ctx, NULL, &len, RAW(data), LENGTH(data)) > 0);
  unsigned char *buf = OPENSSL_malloc(len);
  int ok = EVP_PKEY_decrypt(ctx, buf, &len, RAW(data), LENGTH(data)) > 0;
  EVP_PKEY_CTX_free(ctx);
  if(!ok){
    OPENSSL_free(buf);
    bail(0);
  }
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

static int get_hashtype(SEXP hash){
  switch(Rf_length(hash)){
  case 16:
    return NID_md5;
  case 20:
    return NID_sha1;
  case 32:
    return NID_sha256;
  }
  Rf_error("RSA hash must be length 16, 20, or 32");
}

// This is a legacy function that ignores FIPS-mode
SEXP R_rsa_sign(SEXP hash, SEXP keydata){
  const unsigned char *ptr = RAW(keydata);
  RSA *rsa = d2i_RSAPrivateKey(NULL, &ptr, LENGTH(keydata));
  bail(!!rsa);
  unsigned int siglen;
  unsigned char *sig = OPENSSL_malloc(RSA_size(rsa));
  bail(RSA_sign(get_hashtype(hash),  RAW(hash), Rf_length(hash), sig, &siglen, rsa) == 1);
  RSA_free(rsa);
  SEXP res = Rf_allocVector(RAWSXP, siglen);
  memcpy(RAW(res), sig, siglen);
  OPENSSL_free(sig);
  return res;
}
