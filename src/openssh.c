#include <Rinternals.h>
#include <string.h>
#include "apple.h"
#include "utils.h"
#include <openssl/pem.h>
#include <openssl/bn.h>

/* Manuall compose public keys from bignum values */
SEXP R_rsa_build(SEXP expdata, SEXP moddata){
  RSA *rsa = RSA_new();
  rsa->e = BN_new();
  rsa->n = BN_new();
  bail(!!BN_bin2bn(RAW(expdata), LENGTH(expdata), rsa->e));
  bail(!!BN_bin2bn(RAW(moddata), LENGTH(moddata), rsa->n));
  unsigned char *buf = NULL;
  int len = i2d_RSA_PUBKEY(rsa, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  free(buf);
  return res;
}

SEXP R_rsa_decompose(SEXP bin){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(bin)));
  SEXP res = PROTECT(allocVector(VECSXP, 2));
  SEXP exp = PROTECT(allocVector(RAWSXP, BN_num_bytes(rsa->e)));
  SEXP mod = PROTECT(allocVector(RAWSXP, BN_num_bytes(rsa->n) + 1));
  RAW(mod)[0] = '\0';
  bail(BN_bn2bin(rsa->e, RAW(exp)));
  bail(BN_bn2bin(rsa->n, RAW(mod) + 1));
  SET_VECTOR_ELT(res, 0, exp);
  SET_VECTOR_ELT(res, 1, mod);
  UNPROTECT(3);
  return res;
}

// See https://tools.ietf.org/html/rfc4253: ... the "ssh-dss" key format has ...
SEXP R_dsa_build(SEXP p, SEXP q, SEXP g, SEXP y){
  DSA *dsa = DSA_new();
  dsa->p = BN_new();
  dsa->q = BN_new();
  dsa->g = BN_new();
  dsa->pub_key = BN_new();
  bail(!!BN_bin2bn(RAW(p), LENGTH(p), dsa->p));
  bail(!!BN_bin2bn(RAW(q), LENGTH(q), dsa->q));
  bail(!!BN_bin2bn(RAW(g), LENGTH(g), dsa->g));
  bail(!!BN_bin2bn(RAW(y), LENGTH(y), dsa->pub_key));
  unsigned char *buf = NULL;
  int len = i2d_DSA_PUBKEY(dsa, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  free(buf);
  return res;
}

SEXP R_dsa_decompose(SEXP bin){
  DSA *dsa = DSA_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_DSA_PUBKEY(&dsa, &ptr, LENGTH(bin)));
  SEXP res = PROTECT(allocVector(VECSXP, 4));
  SET_VECTOR_ELT(res, 0, allocVector(RAWSXP, BN_num_bytes(dsa->p) + 1));
  SET_VECTOR_ELT(res, 1, allocVector(RAWSXP, BN_num_bytes(dsa->q) + 1));
  SET_VECTOR_ELT(res, 2, allocVector(RAWSXP, BN_num_bytes(dsa->g) + 1));
  SET_VECTOR_ELT(res, 3, allocVector(RAWSXP, BN_num_bytes(dsa->pub_key)));
  RAW(VECTOR_ELT(res, 0))[0] = '\0';
  RAW(VECTOR_ELT(res, 1))[0] = '\0';
  RAW(VECTOR_ELT(res, 2))[0] = '\0';
  bail(BN_bn2bin(dsa->p, RAW(VECTOR_ELT(res, 0)) + 1));
  bail(BN_bn2bin(dsa->q, RAW(VECTOR_ELT(res, 1)) + 1));
  bail(BN_bn2bin(dsa->g, RAW(VECTOR_ELT(res, 2)) + 1));
  bail(BN_bn2bin(dsa->pub_key, RAW(VECTOR_ELT(res, 3))));
  UNPROTECT(1);
  return res;
}

SEXP R_ecdsa_build(SEXP x, SEXP y){
  EC_KEY *pubkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY_set_asn1_flag(pubkey, OPENSSL_EC_NAMED_CURVE);
  if(!EC_KEY_set_public_key_affine_coordinates(pubkey, BN_bin2bn(RAW(x), LENGTH(x), NULL), BN_bin2bn(RAW(y), LENGTH(y), NULL)))
    error("Failed to construct EC key. Perhaps invalid point or curve.");
  unsigned char *buf = NULL;
  int len = i2d_EC_PUBKEY(pubkey, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  free(buf);
  return res;
}

SEXP R_ecdsa_decompose(SEXP bin){
  EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_EC_PUBKEY(&ec, &ptr, LENGTH(bin)));
  const EC_POINT *pubkey = EC_KEY_get0_public_key(ec);
  const EC_GROUP *group = EC_KEY_get0_group(ec);
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  bail(EC_POINT_get_affine_coordinates_GFp(group, pubkey, x, y, ctx));
  SEXP res = PROTECT(allocVector(VECSXP, 2));
  SET_VECTOR_ELT(res, 0, allocVector(RAWSXP, BN_num_bytes(x)));
  SET_VECTOR_ELT(res, 1, allocVector(RAWSXP, BN_num_bytes(y)));
  bail(BN_bn2bin(x, RAW(VECTOR_ELT(res, 0))));
  bail(BN_bn2bin(y, RAW(VECTOR_ELT(res, 1))));
  BN_free(x);
  BN_free(y);
  UNPROTECT(1);
  return res;
}
