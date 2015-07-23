#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include <openssl/pem.h>
#include <openssl/bn.h>

void raise_error();
void bail(int out);

SEXP R_write_pkcs8(RSA *rsa){
  //Rprintf("Public key: d: %d, e: %d, n:%d, p:%p, q:%d\n", rsa->d, rsa->e, rsa->n, rsa->p, rsa->q);
  int len = i2d_RSA_PUBKEY(rsa, NULL);
  bail(len);
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  setAttrib(res, R_ClassSymbol, mkString("rsa.pubkey"));
  UNPROTECT(1);
  unsigned char *ptr = RAW(res);
  bail(i2d_RSA_PUBKEY(rsa, &(ptr)));
  return res;
}

SEXP R_write_rsa_private(RSA *rsa){
  //Rprintf("Private key: d: %d, e: %d, n:%d, p:%p, q:%d\n", rsa->d, rsa->e, rsa->n, rsa->p, rsa->q);
  int len = i2d_RSAPrivateKey(rsa, NULL);
  bail(len);
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  setAttrib(res, R_ClassSymbol, mkString("rsa.private"));
  UNPROTECT(1);
  unsigned char *ptr = RAW(res);
  bail(i2d_RSAPrivateKey(rsa, &(ptr)));
  return res;
}

SEXP R_priv2pub(SEXP bin){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(bin)));
  return R_write_pkcs8(rsa);
}

SEXP R_parse_pkcs1(SEXP input, SEXP type){
  RSA *rsa = RSA_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  bail(!!PEM_read_bio_RSAPublicKey(mem, &rsa, NULL, NULL));
  bail(EVP_PKEY_assign_RSA(EVP_PKEY_new(), rsa));
  return R_write_pkcs8(rsa);
}

SEXP R_parse_pkcs8(SEXP input){
  RSA *rsa = RSA_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  bail(!!PEM_read_bio_RSA_PUBKEY(mem, &rsa, NULL, NULL));
  bail(EVP_PKEY_assign_RSA(EVP_PKEY_new(), rsa));
  return R_write_pkcs8(rsa);
}

SEXP R_parse_rsa_private(SEXP input){
  EVP_PKEY *key = EVP_PKEY_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  bail(!!PEM_read_bio_PrivateKey(mem, &key, NULL, NULL));
  RSA *rsa = EVP_PKEY_get1_RSA(key);
  return R_write_rsa_private(rsa);
}

SEXP R_rsa_build(SEXP expdata, SEXP moddata){
  RSA *rsa = RSA_new();
  rsa->e = BN_new();
  rsa->n = BN_new();
  bail(!!BN_bin2bn(RAW(expdata), LENGTH(expdata), rsa->e));
  bail(!!BN_bin2bn(RAW(moddata), LENGTH(moddata), rsa->n));
  return R_write_pkcs8(rsa);
}

SEXP R_rsa_encrypt(SEXP data, SEXP keydata) {
  static unsigned char* buf[8192];
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(keydata);
  bail(!!d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(keydata)));
  int len = RSA_public_encrypt(LENGTH(data), RAW(data), (unsigned char*) buf, rsa, RSA_PKCS1_PADDING);
  bail(len >= 0);
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
  bail(len >= 0);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  return res;
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
