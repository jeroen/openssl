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
  SEXP out = PROTECT(Rf_allocVector(VECSXP, count));
  for(int i = 0; i < count; i++){
    PEM_read_bio(mem, &name, &header, &data, &len);
    SEXP res = PROTECT(Rf_allocVector(VECSXP, 3));
    SET_VECTOR_ELT(res, 0, Rf_mkString(name));
    SET_VECTOR_ELT(res, 1, Rf_mkString(header));
    SET_VECTOR_ELT(res, 2, Rf_allocVector(RAWSXP, (int) len));
    memcpy(RAW(VECTOR_ELT(res, 2)), data, (int) len);
    SET_VECTOR_ELT(out, i, res);
    UNPROTECT(1);
  }
  UNPROTECT(1);
  BIO_free(mem);
  if(name) OPENSSL_free(name);
  if(header) OPENSSL_free(header);
  if(data) OPENSSL_free(data);
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
  EVP_PKEY_free(pkey);
  bail(len);
  SEXP res = Rf_allocVector(RAWSXP, len);
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
  EVP_PKEY_free(pkey);
  bail(len);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_parse_pem_cert(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  X509 *cert = PEM_read_bio_X509(mem, NULL, password_cb, NULL);
  unsigned char *buf = NULL;
  int len = i2d_X509(cert, &buf);
  X509_free(cert);
  bail(len);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

/* Legacy pubkey format */
SEXP R_parse_pem_pubkey_pkcs1(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  unsigned char *data = NULL;
  long datalen = 0;
  bail(PEM_bytes_read_bio(&data, &datalen, NULL, PEM_STRING_RSA_PUBLIC, mem, password_cb, NULL));
  BIO_free(mem);
  const unsigned char *ptr = data;
  EVP_PKEY *pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &ptr, datalen);
  OPENSSL_free(data);
  bail(!!pkey);
  unsigned char *buf = NULL;
  int len = i2d_PUBKEY(pkey, &buf);
  EVP_PKEY_free(pkey);
  bail(len);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

/* Legacy rsa key format */
SEXP R_parse_pem_key_pkcs1(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(mem, NULL, password_cb, NULL);
  BIO_free(mem);
  bail(!!pkey);
  if(EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA){
    EVP_PKEY_free(pkey);
    Rf_error("Key is not an RSA key");
  }
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  EVP_PKEY_free(pkey);
  bail(len);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}
