#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include "utils.h"

SEXP R_rsa_encrypt(SEXP data, SEXP keydata, SEXP oaep) {
  const unsigned char *ptr = RAW(keydata);
  RSA *rsa = d2i_RSA_PUBKEY(NULL, &ptr, LENGTH(keydata));
  int pad = Rf_asLogical(oaep) ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;
  bail(!!rsa);
  int keysize = RSA_size(rsa);
  unsigned char* buf = OPENSSL_malloc(keysize);
  int len = RSA_public_encrypt(LENGTH(data), RAW(data), buf, rsa, pad);
  bail(len > 0);
  RSA_free(rsa);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_rsa_decrypt(SEXP data, SEXP keydata, SEXP oaep){
  const unsigned char *ptr = RAW(keydata);
  RSA *rsa = d2i_RSAPrivateKey(NULL, &ptr, LENGTH(keydata));
  int pad = Rf_asLogical(oaep) ? RSA_PKCS1_OAEP_PADDING : RSA_PKCS1_PADDING;
  bail(!!rsa);
  int keysize = RSA_size(rsa);
  unsigned char* buf = OPENSSL_malloc(keysize);
  int len = RSA_private_decrypt(LENGTH(data), RAW(data), buf, rsa, pad);
  bail(len > 0);
  RSA_free(rsa);
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
