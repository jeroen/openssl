#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include "utils.h"

SEXP R_rsa_encrypt(SEXP data, SEXP keydata) {
  const unsigned char *ptr = RAW(keydata);
  RSA *rsa = d2i_RSA_PUBKEY(NULL, &ptr, LENGTH(keydata));
  bail(!!rsa);
  int keysize = RSA_size(rsa);
  unsigned char* buf = OPENSSL_malloc(keysize);
  int len = RSA_public_encrypt(LENGTH(data), RAW(data), buf, rsa, RSA_PKCS1_PADDING);
  bail(len > 0);
  RSA_free(rsa);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_rsa_decrypt(SEXP data, SEXP keydata){
  const unsigned char *ptr = RAW(keydata);
  RSA *rsa = d2i_RSAPrivateKey(NULL, &ptr, LENGTH(keydata));
  bail(!!rsa);
  int keysize = RSA_size(rsa);
  unsigned char* buf = OPENSSL_malloc(keysize);
  int len = RSA_private_decrypt(LENGTH(data), RAW(data), buf, rsa, RSA_PKCS1_PADDING);
  bail(len > 0);
  RSA_free(rsa);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}
