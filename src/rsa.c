#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <openssl/pem.h>

SEXP R_rsa_encrypt(SEXP data, SEXP keydata) {
  static unsigned char* buf[8192];
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(keydata);
  bail(!!d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(keydata)));
  int len = RSA_public_encrypt(LENGTH(data), RAW(data), (unsigned char*) buf, rsa, RSA_PKCS1_PADDING);
  bail(len > 0);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  return res;
}

SEXP R_rsa_decrypt(SEXP data, SEXP keydata){
  static unsigned char* buf[8192];
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(keydata);
  bail(!!d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(keydata)));
  int len = RSA_private_decrypt(LENGTH(data), RAW(data), (unsigned char*) buf, rsa, RSA_PKCS1_PADDING);
  bail(len > 0);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  return res;
}
