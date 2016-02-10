#include <Rinternals.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include "utils.h"

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
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
  free(buf);
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
  free(buf);
  return res;
}

SEXP R_keygen_ecdsa(SEXP curve){
#ifndef OPENSSL_NO_EC
  int nid = my_nist2nid(CHAR(STRING_ELT(curve, 0)));
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  bail(!!ctx);
  bail(EVP_PKEY_keygen_init(ctx) > 0);
  bail(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid));
  EVP_PKEY *pkey = NULL;
  bail(EVP_PKEY_keygen(ctx, &pkey) > 0);
  EC_KEY_set_asn1_flag(EVP_PKEY_get1_EC_KEY(pkey), OPENSSL_EC_NAMED_CURVE);
  unsigned char *buf = NULL;
  int len = i2d_PrivateKey(pkey, &buf);
  bail(len);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  free(buf);
  return res;
#else //OPENSSL_NO_EC
  Rf_error("OpenSSL has been configured without EC support");
#endif //OPENSSL_NO_EC
}
