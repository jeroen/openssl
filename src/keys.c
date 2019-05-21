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
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
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
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
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
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
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
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
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
  bail(!!key);
  unsigned char *buf = NULL;
  int len = i2d_PUBKEY(key, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
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
  return mkString(keytype);
}

int ec_bitsize(int nid){
  switch(nid){
  case NID_X9_62_prime256v1:
    return 256;
  case NID_secp384r1:
    return 384;
  case NID_secp521r1:
    return 521;
  }
  return 0;
}

SEXP R_pubkey_bitsize(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PUBKEY_bio(mem, NULL);
  BIO_free(mem);
  if(!pkey)
    return R_NilValue;
  int size = 0;
  const BIGNUM * val;
  switch(EVP_PKEY_base_id(pkey)){
  case EVP_PKEY_RSA:
    MY_RSA_get0_key(EVP_PKEY_get1_RSA(pkey), &val, NULL, NULL);
    size = BN_num_bits(val);
    break;
  case EVP_PKEY_DSA:
    MY_DSA_get0_pqg(EVP_PKEY_get1_DSA(pkey), &val, NULL, NULL);
    size = BN_num_bits(val);
    break;
#ifdef EVP_PKEY_ED25519
  case EVP_PKEY_ED25519:
  case EVP_PKEY_X25519:
    size = 256;
    break;
#endif
#ifndef OPENSSL_NO_EC
  case EVP_PKEY_EC:
    size = ec_bitsize(EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get1_EC_KEY(pkey))));
    break;
#endif //OPENSSL_NO_EC
  default:
    Rf_error("Unsupported key type: %d", EVP_PKEY_base_id(pkey));
  }
  EVP_PKEY_free(pkey);
  return ScalarInteger(size);
}
