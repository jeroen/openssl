#include <Rinternals.h>
#include <string.h>
#include "apple.h"
#include "utils.h"
#include <openssl/pem.h>
#include <openssl/bn.h>

int password_cb(char *buf, int max_size, int rwflag, void *ctx){
  if(!ctx)
    error("No password callback supplied.");

  SEXP cb = (SEXP) ctx;
  int len;

  /* no password */
  if(isNull(cb)){
    return 0;
  }

  /* case where password is a hardcoded string */
  if(isString(cb)){
    len = LENGTH(STRING_ELT(cb, 0));
    len = MIN(len, max_size);
    memcpy(buf, CHAR(STRING_ELT(cb, 0)), len);
    return len;
  }

  /* case where password is an R function */
  if(isFunction(cb)){
    int err;
    SEXP call = PROTECT(LCONS(cb, LCONS(mkString("Please enter private key passphrase: "), R_NilValue)));
    SEXP res = PROTECT(R_tryEval(call, R_GlobalEnv, &err));
    if(err || !isString(res)){
      UNPROTECT(2);
      error("Password callback did not return a string value");
    }
    len = LENGTH(STRING_ELT(res, 0));
    len = MIN(len, max_size);
    memcpy(buf, CHAR(STRING_ELT(res, 0)), len);
    UNPROTECT(2);
    return len;
  }
  error("Callback must be string or function");
}

/* parses any pem file, does not support passwords */
SEXP R_parse_pem(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  char *name = NULL;
  char *header = NULL;
  unsigned char *data = NULL;
  long len = 0;
  PEM_read_bio(mem, &name, &header, &data, &len);
  BIO_free(mem);
  if(!len) return R_NilValue;
  SEXP res = PROTECT(allocVector(VECSXP, 3));
  SET_VECTOR_ELT(res, 0, mkString(name));
  SET_VECTOR_ELT(res, 1, mkString(header));
  SET_VECTOR_ELT(res, 2, allocVector(RAWSXP, (int) len));
  memcpy(RAW(VECTOR_ELT(res, 2)), data, (int) len);
  UNPROTECT(1);
  return res;
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
  free(buf);
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
  free(buf);
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
  free(buf);
  return res;
}

/* Legacy pubkey format */
SEXP R_parse_pem_pkcs1(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  RSA *rsa = PEM_read_bio_RSAPublicKey(mem, NULL, password_cb, NULL);
  bail(!!rsa);
  unsigned char *buf = NULL;
  int len = i2d_RSA_PUBKEY(rsa, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  free(buf);
  return res;
}

SEXP R_parse_der_pubkey(SEXP input){
  const unsigned char *ptr = RAW(input);
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &ptr, LENGTH(input));
  bail(!!pkey);
  unsigned char *buf = NULL;
  int len = i2d_PUBKEY(pkey, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  free(buf);
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
  free(buf);
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
  free(buf);
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
  free(buf);
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
  free(buf);
  return res;
}

SEXP R_pubkey_type(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PUBKEY_bio(mem, NULL);
  BIO_free(mem);
  if(!pkey)
    return R_NilValue;
  char *keytype;
  switch(EVP_PKEY_type(pkey->type)){
  case EVP_PKEY_RSA:
    keytype = "rsa";
    break;
  case EVP_PKEY_DSA:
    keytype = "dsa";
    break;
  case EVP_PKEY_EC:
    keytype = "ecdsa";
    break;
  default:
    Rf_error("Unsupported key type: %d", EVP_PKEY_type(pkey->type));
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
  switch(EVP_PKEY_type(pkey->type)){
  case EVP_PKEY_RSA:
    size = BN_num_bits(EVP_PKEY_get1_RSA(pkey)->n);
    break;
  case EVP_PKEY_DSA:
    size = BN_num_bits(EVP_PKEY_get1_DSA(pkey)->p);
    break;
  case EVP_PKEY_EC:
    size = ec_bitsize(EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get1_EC_KEY(pkey))));
    break;
  default:
    Rf_error("Unsupported key type: %d", EVP_PKEY_type(pkey->type));
  }
  EVP_PKEY_free(pkey);
  return ScalarInteger(size);
}
