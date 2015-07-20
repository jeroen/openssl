#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include <openssl/pem.h>

void raise_error();
void bail(int out);

SEXP R_write_pkcs8(RSA *rsa){
  int len = i2d_RSA_PUBKEY(rsa, NULL);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  unsigned char *ptr = RAW(res);
  bail(i2d_RSA_PUBKEY(rsa, &(ptr)));
  return res;
}

SEXP R_write_rsa_private(RSA *rsa){
  //Rprintf("Private key: d: %d, e: %d, n:%d, p:%p, q:%d\n", rsa->d, rsa->e, rsa->n, rsa->p, rsa->q);
  int len = i2d_RSAPrivateKey(rsa, NULL);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
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
