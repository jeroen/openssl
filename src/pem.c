#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "utils.h"

/* parses any pem file, does not support passwords */
SEXP R_parse_pem(SEXP input){
  char *name = NULL;
  char *header = NULL;
  unsigned char *data = NULL;
  long len = 0;
  int count = 0;
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  while(PEM_read_bio(mem, &name, &header, &data, &len) && len)
    count++;
  ERR_clear_error();
  BIO_free(mem);
  mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  SEXP out = PROTECT(allocVector(VECSXP, count));
  for(int i = 0; i < count; i++){
    PEM_read_bio(mem, &name, &header, &data, &len);
    SEXP res = PROTECT(allocVector(VECSXP, 3));
    SET_VECTOR_ELT(res, 0, mkString(name));
    SET_VECTOR_ELT(res, 1, mkString(header));
    SET_VECTOR_ELT(res, 2, allocVector(RAWSXP, (int) len));
    memcpy(RAW(VECTOR_ELT(res, 2)), data, (int) len);
    SET_VECTOR_ELT(out, i, res);
    UNPROTECT(1);
  }
  UNPROTECT(1);
  BIO_free(mem);
  ERR_clear_error();
  return out;
}

SEXP R_parse_pem_key(SEXP input, SEXP password){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(mem, NULL, password_cb, password);
  BIO_free(mem);
  bail(!!pkey);
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_parse_pem_pubkey(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(mem, NULL, password_cb, NULL);
  BIO_free(mem);
  bail(!!pkey);
  unsigned char *buf = NULL;
  int len = i2d_PUBKEY(pkey, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_parse_pem_cert(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  X509 *cert = PEM_read_bio_X509(mem, NULL, password_cb, NULL);
  unsigned char *buf = NULL;
  int len = i2d_X509(cert, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

/* Legacy pubkey format */
SEXP R_parse_pem_pubkey_pkcs1(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  RSA *rsa = PEM_read_bio_RSAPublicKey(mem, NULL, password_cb, NULL);
  bail(!!rsa);
  unsigned char *buf = NULL;
  int len = i2d_RSA_PUBKEY(rsa, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

/* Legacy rsa key format */
SEXP R_parse_pem_key_pkcs1(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  RSA *rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, password_cb, NULL);
  bail(!!rsa);
  unsigned char *buf = NULL;
  int len = i2d_RSAPrivateKey(rsa, &buf);
  bail(len);
  RSA_free(rsa);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}
