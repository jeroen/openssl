#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include "utils.h"
#include "compatibility.h"

SEXP R_parse_der_pubkey(SEXP input){
  const unsigned char *ptr = RAW(input);
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &ptr, LENGTH(input));
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

SEXP R_parse_der_key(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
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

SEXP R_parse_der_cert(SEXP input){
  const unsigned char *ptr = RAW(input);
  X509 *cert = d2i_X509(NULL, &ptr, LENGTH(input));
  bail(!!cert);
  unsigned char *buf = NULL;
  int len = i2d_X509(cert, &buf);
  X509_free(cert);
  bail(len);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

/* Convert private to public key */
SEXP R_derive_pubkey(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
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

/* Convert cert to public key */
SEXP R_cert_pubkey(SEXP input){
  const unsigned char *ptr = RAW(input);
  X509 *cert = d2i_X509(NULL, &ptr, LENGTH(input));
  bail(!!cert);
  EVP_PKEY *key = X509_get_pubkey(cert);
  X509_free(cert);
  bail(!!key);
  unsigned char *buf = NULL;
  int len = i2d_PUBKEY(key, &buf);
  EVP_PKEY_free(key);
  bail(len);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_pubkey_type(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PUBKEY_bio(mem, NULL);
  BIO_free(mem);
  if(!pkey)
    return R_NilValue;
  const char *keytype;
  switch(EVP_PKEY_base_id(pkey)){
  case EVP_PKEY_RSA:
    keytype = "rsa";
    break;
  case EVP_PKEY_DSA:
    keytype = "dsa";
    break;
  case EVP_PKEY_EC:
    keytype = "ecdsa";
    break;
#ifdef EVP_PKEY_ED25519
  case EVP_PKEY_X25519:
    keytype = "x25519";
    break;
  case EVP_PKEY_ED25519:
    keytype = "ed25519";
    break;
#endif
  default:
    Rf_error("Unsupported key type: %d", EVP_PKEY_base_id(pkey));
  }
  EVP_PKEY_free(pkey);
  return Rf_mkString(keytype);
}

SEXP R_pubkey_bitsize(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PUBKEY_bio(mem, NULL);
  BIO_free(mem);
  if(!pkey)
    return R_NilValue;
  int size = 0;
  switch(EVP_PKEY_base_id(pkey)){
  case EVP_PKEY_RSA:
  case EVP_PKEY_DSA:
#ifndef OPENSSL_NO_EC
  case EVP_PKEY_EC:
#endif
    size = EVP_PKEY_bits(pkey);
    break;
#ifdef EVP_PKEY_ED25519
  case EVP_PKEY_ED25519:
  case EVP_PKEY_X25519:
    size = 256;
    break;
#endif
  default:
    Rf_error("Unsupported key type: %d", EVP_PKEY_base_id(pkey));
  }
  EVP_PKEY_free(pkey);
  return Rf_ScalarInteger(size);
}
