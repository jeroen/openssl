#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <openssl/pem.h>

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
