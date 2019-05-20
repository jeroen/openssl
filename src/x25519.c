#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "utils.h"

#ifdef EVP_PKEY_ED25519
#define HAS_ECX
#endif

static SEXP R_read_raw_key(SEXP x, int type){
#ifdef HAS_ECX
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(type, NULL, RAW(x), Rf_length(x));
  bail(!!pkey);
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len);
  EVP_PKEY_free(pkey);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}

static SEXP R_read_raw_pubkey(SEXP x, int type){
#ifdef HAS_ECX
  EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(type, NULL, RAW(x), Rf_length(x));
  bail(!!pkey);
  unsigned char *buf = NULL;
  int len = i2d_PUBKEY(pkey, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}

SEXP R_read_raw_key_ed25519(SEXP x){
#ifdef HAS_ECX
  return R_read_raw_key(x, EVP_PKEY_ED25519);
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}

SEXP R_read_raw_pubkey_ed25519(SEXP x){
#ifdef HAS_ECX
  return R_read_raw_pubkey(x, EVP_PKEY_ED25519);
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}

SEXP R_read_raw_key_x25519(SEXP x){
#ifdef HAS_ECX
  return R_read_raw_key(x, EVP_PKEY_X25519);
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}

SEXP R_read_raw_pubkey_x25519(SEXP x){
#ifdef HAS_ECX
  return R_read_raw_pubkey(x, EVP_PKEY_X25519);
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}

SEXP R_write_raw_key(SEXP input){
#ifdef HAS_ECX
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  size_t len = 0;
  bail(EVP_PKEY_get_raw_private_key(pkey, NULL, &len));
  SEXP res = Rf_allocVector(RAWSXP, len);
  bail(EVP_PKEY_get_raw_private_key(pkey, RAW(res), &len));
  return res;
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}

SEXP R_write_raw_pubkey(SEXP input){
#ifdef HAS_ECX
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PUBKEY_bio(mem, NULL);
  BIO_free(mem);
  size_t len = 0;
  bail(EVP_PKEY_get_raw_public_key(pkey, NULL, &len));
  SEXP res = Rf_allocVector(RAWSXP, len);
  bail(EVP_PKEY_get_raw_public_key(pkey, RAW(res), &len));
  return res;
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}
