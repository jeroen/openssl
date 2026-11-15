#include <Rinternals.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include "utils.h"
#include "compatibility.h"

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
  bail(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, Rf_asInteger(bits)) > 0);
  EVP_PKEY *pkey = NULL;
  bail(EVP_PKEY_keygen(ctx, &pkey) > 0);
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_keygen_dsa(SEXP bits){
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
  bail(!!pctx);
  bail(EVP_PKEY_paramgen_init(pctx) > 0);
  bail(EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, Rf_asInteger(bits)) > 0);
  EVP_PKEY *params = NULL;
  bail(EVP_PKEY_paramgen(pctx, &params) > 0);
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(params, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_keygen_init(ctx) > 0);
  EVP_PKEY *pkey = NULL;
  bail(EVP_PKEY_keygen(ctx, &pkey) > 0);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(params);
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len);
  EVP_PKEY_free(pkey);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_keygen_ecdsa(SEXP curve){
#ifndef OPENSSL_NO_EC
  int nid = my_nist2nid(CHAR(STRING_ELT(curve, 0)));
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  bail(!!pctx);
  bail(EVP_PKEY_paramgen_init(pctx) > 0);
  bail(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) > 0);
#ifdef HAS_OPENSSL11_API
  bail(EVP_PKEY_CTX_set_ec_param_enc(pctx, OPENSSL_EC_NAMED_CURVE) > 0);
#endif
  EVP_PKEY *params = NULL;
  bail(EVP_PKEY_paramgen(pctx, &params) > 0);
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(params, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_keygen_init(ctx) > 0);
  EVP_PKEY *pkey = NULL;
  bail(EVP_PKEY_keygen(ctx, &pkey) > 0);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(params);
#ifndef HAS_OPENSSL11_API
  EC_KEY_set_asn1_flag(MY_EVP_PKEY_get0_EC_KEY(pkey), OPENSSL_EC_NAMED_CURVE);
#endif
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len > 0);
  EVP_PKEY_free(pkey);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#else //OPENSSL_NO_EC
  Rf_error("OpenSSL has been configured without EC support");
#endif //OPENSSL_NO_EC
}

SEXP R_keygen_x25519(void){
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
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}

SEXP R_keygen_ed25519(void){
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
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#else
  Rf_error("Curve25519 requires OpenSSL 1.1.1 or newer.");
#endif
}
