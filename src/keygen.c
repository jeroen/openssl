#include <Rinternals.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include "utils.h"

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

#ifdef EVP_PKEY_ED25519
#define HAS_ECX
#endif

SEXP R_keygen_rsa(SEXP bits){
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_keygen_init(ctx) > 0);
  bail(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, asInteger(bits)) > 0);
  EVP_PKEY *pkey = NULL;
  bail(EVP_PKEY_keygen(ctx, &pkey) > 0);
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_keygen_dsa(SEXP bits){
  DSA *dsa = DSA_new();
  DSA_generate_parameters_ex(dsa, asInteger(bits), NULL, 0, NULL, NULL, NULL);
  bail(DSA_generate_key(dsa));
  unsigned char *buf = NULL;
  int len = i2d_DSAPrivateKey(dsa, &buf);
  bail(len);
  DSA_free(dsa);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_keygen_ecdsa(SEXP curve){
#ifndef OPENSSL_NO_EC
  int nid = my_nist2nid(CHAR(STRING_ELT(curve, 0)));
  EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
  bail(!!eckey);
  bail(EC_KEY_generate_key(eckey) > 0);
  EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
  EVP_PKEY *pkey = EVP_PKEY_new();
  bail(!!pkey);
  bail(EVP_PKEY_assign_EC_KEY(pkey, eckey) > 0);
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len > 0);
  EVP_PKEY_free(pkey);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#else //OPENSSL_NO_EC
  Rf_error("OpenSSL has been configured without EC support");
#endif //OPENSSL_NO_EC
}

SEXP R_keygen_x25519(){
#ifdef HAS_ECX
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_keygen_init(ctx) > 0);
  EVP_PKEY *pkey = NULL;
  bail(EVP_PKEY_keygen(ctx, &pkey) > 0);
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}

SEXP R_keygen_ed25519(){
#ifdef HAS_ECX
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_keygen_init(ctx) > 0);
  EVP_PKEY *pkey = NULL;
  bail(EVP_PKEY_keygen(ctx, &pkey) > 0);
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}
