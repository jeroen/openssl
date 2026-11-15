#include <Rinternals.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include "utils.h"
#include "compatibility.h"

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

#ifdef HAS_OPENSSL3_API
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#endif

/* BN_bn2bin() drops leading zeros which can alter openssh fingerprint */
SEXP bignum_to_r_size(const BIGNUM *bn, int bytes){
  int bits = BN_num_bits(bn);
  if(bytes == 0)
    bytes = (bits/8) + 1;
  int numbytes = BN_num_bytes(bn);
  int diff = bytes - numbytes;
  SEXP res = PROTECT(Rf_allocVector(RAWSXP, bytes));
  Rf_setAttrib(res, R_ClassSymbol, Rf_mkString("bignum"));
  UNPROTECT(1);
  unsigned char *ptr = RAW(res);
  memset(ptr, 0, diff);
  ptr += diff;
  BN_bn2bin(bn, ptr);
  return res;
}

SEXP bignum_to_r(const BIGNUM *bn){
  return bignum_to_r_size(bn, 0);
}

BIGNUM* new_bignum_from_r(SEXP input){
  BIGNUM *bn = BN_bin2bn(RAW(input), LENGTH(input), NULL);
  bail(!!bn);
  return bn;
}

#ifdef HAS_OPENSSL3_API
/* The param builder stores BIGNUMs by reference, so they live in a BN_CTX until the key is built */
static void push_bignum(OSSL_PARAM_BLD *bld, BN_CTX *bnctx, const char *key, SEXP input){
  BIGNUM *bn = BN_CTX_get(bnctx);
  bail(bn && BN_bin2bn(RAW(input), LENGTH(input), bn));
  bail(OSSL_PARAM_BLD_push_BN(bld, key, bn));
}

/* Builds the key and frees the builder and BN_CTX. Returns NULL on failure. */
static EVP_PKEY *pkey_fromdata(const char *type, int selection, OSSL_PARAM_BLD *bld, BN_CTX *bnctx){
  EVP_PKEY *pkey = NULL;
  OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
  if(params && ctx && EVP_PKEY_fromdata_init(ctx) > 0)
    EVP_PKEY_fromdata(ctx, &pkey, selection, params);
  EVP_PKEY_CTX_free(ctx);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);
  BN_CTX_end(bnctx);
  BN_CTX_free(bnctx);
  return pkey;
}

static SEXP pkey_get_bignum(EVP_PKEY *pkey, const char *key, int bytes){
  BIGNUM *bn = NULL;
  bail(EVP_PKEY_get_bn_param(pkey, key, &bn));
  SEXP res = bignum_to_r_size(bn, bytes);
  BN_clear_free(bn);
  return res;
}

static EVP_PKEY *pkey_from_der(SEXP bin, int type, int private){
  const unsigned char *ptr = RAW(bin);
  EVP_PKEY *pkey = private ? d2i_PrivateKey(type, NULL, &ptr, LENGTH(bin)) : d2i_PUBKEY(NULL, &ptr, LENGTH(bin));
  bail(!!pkey);
  if(EVP_PKEY_base_id(pkey) != type){
    EVP_PKEY_free(pkey);
    Rf_error("Unexpected key type");
  }
  return pkey;
}

/* Serializes and frees the key: public keys as SubjectPublicKeyInfo, private keys in traditional format */
static SEXP pkey_to_der(EVP_PKEY *pkey, int private){
  unsigned char *buf = NULL;
  int len = private ? i2d_PrivateKey(pkey, &buf) : i2d_PUBKEY(pkey, &buf);
  EVP_PKEY_free(pkey);
  bail(len > 0);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}
#endif

/* Manuall compose public keys from bignum values */
SEXP R_rsa_pubkey_build(SEXP expdata, SEXP moddata){
#ifdef HAS_OPENSSL3_API
  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  BN_CTX *bnctx = BN_CTX_new();
  bail(bld && bnctx);
  BN_CTX_start(bnctx);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_N, moddata);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_E, expdata);
  EVP_PKEY *pkey = pkey_fromdata("RSA", EVP_PKEY_PUBLIC_KEY, bld, bnctx);
  bail(!!pkey);
  return pkey_to_der(pkey, 0);
#else
  RSA *rsa = RSA_new();
  MY_RSA_set0_key(rsa, new_bignum_from_r(moddata), new_bignum_from_r(expdata), NULL);
  unsigned char *buf = NULL;
  int len = i2d_RSA_PUBKEY(rsa, &buf);
  bail(len);
  RSA_free(rsa);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#endif
}

SEXP R_rsa_key_build(SEXP n, SEXP e, SEXP d, SEXP qi, SEXP p, SEXP q, SEXP dp, SEXP dq){
#ifdef HAS_OPENSSL3_API
  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  BN_CTX *bnctx = BN_CTX_new();
  bail(bld && bnctx);
  BN_CTX_start(bnctx);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_N, n);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_E, e);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_D, d);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_FACTOR1, p);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_FACTOR2, q);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qi);
  EVP_PKEY *pkey = pkey_fromdata("RSA", EVP_PKEY_KEYPAIR, bld, bnctx);
  bail(!!pkey);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
  bail(!!ctx);
  int ok = EVP_PKEY_check(ctx);
  EVP_PKEY_CTX_free(ctx);
  if(ok != 1)
    EVP_PKEY_free(pkey);
  bail(ok == 1);
  return pkey_to_der(pkey, 1);
#else
  RSA *rsa = RSA_new();
  MY_RSA_set0_key(rsa, new_bignum_from_r(n), new_bignum_from_r(e), new_bignum_from_r(d));
  MY_RSA_set0_factors(rsa, new_bignum_from_r(p), new_bignum_from_r(q));
  MY_RSA_set0_crt_params(rsa, new_bignum_from_r(dp), new_bignum_from_r(dq), new_bignum_from_r(qi));
  bail(RSA_check_key(rsa));
  unsigned char *buf = NULL;
  int len = i2d_RSAPrivateKey(rsa, &buf);
  bail(len);
  RSA_free(rsa);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#endif
}

SEXP R_rsa_pubkey_decompose(SEXP bin){
#ifdef HAS_OPENSSL3_API
  EVP_PKEY *pkey = pkey_from_der(bin, EVP_PKEY_RSA, 0);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(res, 0, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_E, 0));
  SET_VECTOR_ELT(res, 1, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_N, 0));
  EVP_PKEY_free(pkey);
  UNPROTECT(1);
  return res;
#else
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(bin)));
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 2));
  const BIGNUM *e, *n;
  MY_RSA_get0_key(rsa, &n, &e, NULL);
  SET_VECTOR_ELT(res, 0, bignum_to_r(e));
  SET_VECTOR_ELT(res, 1, bignum_to_r(n));
  UNPROTECT(1);
  return res;
#endif
}

SEXP R_rsa_priv_decompose(SEXP bin){
#ifdef HAS_OPENSSL3_API
  EVP_PKEY *pkey = pkey_from_der(bin, EVP_PKEY_RSA, 1);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 8));
  SET_VECTOR_ELT(res, 0, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_E, 0));
  SET_VECTOR_ELT(res, 1, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_N, 0));
  SET_VECTOR_ELT(res, 2, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, 0));
  SET_VECTOR_ELT(res, 3, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, 0));
  SET_VECTOR_ELT(res, 4, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_D, 0));
  SET_VECTOR_ELT(res, 5, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, 0));
  SET_VECTOR_ELT(res, 6, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, 0));
  SET_VECTOR_ELT(res, 7, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, 0));
  EVP_PKEY_free(pkey);
  UNPROTECT(1);
  return res;
#else
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(bin)));
  const BIGNUM *e, *n, *p, *q, *d, *dmp1, *dmq1, *iqmp;
  MY_RSA_get0_key(rsa, &n, &e, &d);
  MY_RSA_get0_factors(rsa, &p, &q);
  MY_RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 8));
  SET_VECTOR_ELT(res, 0, bignum_to_r(e));
  SET_VECTOR_ELT(res, 1, bignum_to_r(n));
  SET_VECTOR_ELT(res, 2, bignum_to_r(p));
  SET_VECTOR_ELT(res, 3, bignum_to_r(q));
  SET_VECTOR_ELT(res, 4, bignum_to_r(d));
  SET_VECTOR_ELT(res, 5, bignum_to_r(dmp1));
  SET_VECTOR_ELT(res, 6, bignum_to_r(dmq1));
  SET_VECTOR_ELT(res, 7, bignum_to_r(iqmp));
  UNPROTECT(1);
  return res;
#endif
}

// See https://tools.ietf.org/html/rfc4253: ... the "ssh-dss" key format has ...
SEXP R_dsa_pubkey_build(SEXP p, SEXP q, SEXP g, SEXP y){
#ifdef HAS_OPENSSL3_API
  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  BN_CTX *bnctx = BN_CTX_new();
  bail(bld && bnctx);
  BN_CTX_start(bnctx);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_FFC_P, p);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_FFC_Q, q);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_FFC_G, g);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_PUB_KEY, y);
  EVP_PKEY *pkey = pkey_fromdata("DSA", EVP_PKEY_PUBLIC_KEY, bld, bnctx);
  bail(!!pkey);
  return pkey_to_der(pkey, 0);
#else
  DSA *dsa = DSA_new();
  MY_DSA_set0_pqg(dsa, new_bignum_from_r(p), new_bignum_from_r(q), new_bignum_from_r(g));
  MY_DSA_set0_key(dsa, new_bignum_from_r(y), NULL);
  unsigned char *buf = NULL;
  int len = i2d_DSA_PUBKEY(dsa, &buf);
  bail(len);
  DSA_free(dsa);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#endif
}

SEXP R_dsa_key_build(SEXP p, SEXP q, SEXP g, SEXP y, SEXP x){
#ifdef HAS_OPENSSL3_API
  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  BN_CTX *bnctx = BN_CTX_new();
  bail(bld && bnctx);
  BN_CTX_start(bnctx);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_FFC_P, p);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_FFC_Q, q);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_FFC_G, g);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_PUB_KEY, y);
  push_bignum(bld, bnctx, OSSL_PKEY_PARAM_PRIV_KEY, x);
  EVP_PKEY *pkey = pkey_fromdata("DSA", EVP_PKEY_KEYPAIR, bld, bnctx);
  bail(!!pkey);
  return pkey_to_der(pkey, 1);
#else
  DSA *dsa = DSA_new();
  MY_DSA_set0_pqg(dsa, new_bignum_from_r(p), new_bignum_from_r(q), new_bignum_from_r(g));
  MY_DSA_set0_key(dsa, new_bignum_from_r(y), new_bignum_from_r(x));
  unsigned char *buf = NULL;
  int len = i2d_DSAPrivateKey(dsa, &buf);
  bail(len);
  DSA_free(dsa);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#endif
}

SEXP R_dsa_pubkey_decompose(SEXP bin){
#ifdef HAS_OPENSSL3_API
  EVP_PKEY *pkey = pkey_from_der(bin, EVP_PKEY_DSA, 0);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 4));
  SET_VECTOR_ELT(res, 0, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_FFC_P, 0));
  SET_VECTOR_ELT(res, 1, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_FFC_Q, 0));
  SET_VECTOR_ELT(res, 2, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_FFC_G, 0));
  SET_VECTOR_ELT(res, 3, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_PUB_KEY, 0));
  EVP_PKEY_free(pkey);
  UNPROTECT(1);
  return res;
#else
  DSA *dsa = DSA_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_DSA_PUBKEY(&dsa, &ptr, LENGTH(bin)));
  const BIGNUM *p, *q, *g, *pub_key;
  MY_DSA_get0_pqg(dsa, &p, &q, &g);
  MY_DSA_get0_key(dsa, &pub_key, NULL);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 4));
  SET_VECTOR_ELT(res, 0, bignum_to_r(p));
  SET_VECTOR_ELT(res, 1, bignum_to_r(q));
  SET_VECTOR_ELT(res, 2, bignum_to_r(g));
  SET_VECTOR_ELT(res, 3, bignum_to_r(pub_key));
  UNPROTECT(1);
  return res;
#endif
}

SEXP R_dsa_priv_decompose(SEXP bin){
#ifdef HAS_OPENSSL3_API
  EVP_PKEY *pkey = pkey_from_der(bin, EVP_PKEY_DSA, 1);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 5));
  SET_VECTOR_ELT(res, 0, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_FFC_P, 0));
  SET_VECTOR_ELT(res, 1, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_FFC_Q, 0));
  SET_VECTOR_ELT(res, 2, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_FFC_G, 0));
  SET_VECTOR_ELT(res, 3, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_PUB_KEY, 0));
  SET_VECTOR_ELT(res, 4, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_PRIV_KEY, 0));
  EVP_PKEY_free(pkey);
  UNPROTECT(1);
  return res;
#else
  DSA *dsa = DSA_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_DSAPrivateKey(&dsa, &ptr, LENGTH(bin)));
  const BIGNUM *p, *q, *g, *pub_key, *priv_key;
  MY_DSA_get0_pqg(dsa, &p, &q, &g);
  MY_DSA_get0_key(dsa, &pub_key, &priv_key);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 5));
  SET_VECTOR_ELT(res, 0, bignum_to_r(p));
  SET_VECTOR_ELT(res, 1, bignum_to_r(q));
  SET_VECTOR_ELT(res, 2, bignum_to_r(g));
  SET_VECTOR_ELT(res, 3, bignum_to_r(pub_key));
  SET_VECTOR_ELT(res, 4, bignum_to_r(priv_key));
  UNPROTECT(1);
  return res;
#endif
}

// EC_curve_nist2nid only available in recent openssl versions
int my_nist2nid(const char *name){
  if (!strcmp(name, "P-256")){
    return NID_X9_62_prime256v1;
  } else if (!strcmp(name, "P-384")){
    return NID_secp384r1;
  } else if (!strcmp(name, "P-521")){
    return NID_secp521r1;
  }
  return 0;
}

const char *my_nid2nist(int nid){
  switch(nid){
    case NID_X9_62_prime256v1:
      return "P-256";
    case NID_secp384r1:
      return "P-384";
    case NID_secp521r1:
      return "P-521";
  }
  return "";
}

int nid_keysize(int nid){
  switch(nid){
  case NID_X9_62_prime256v1:
    return 32;
  case NID_secp384r1:
    return 48;
  case NID_secp521r1:
    return 66;
  }
  return 0;
}

#if defined(HAS_OPENSSL3_API) && !defined(OPENSSL_NO_EC)
/* Encodes x and y as an uncompressed EC point; buf must hold 1 + 2 * keysize bytes */
static void ec_point_encode(unsigned char *buf, int keysize, SEXP x, SEXP y, BN_CTX *bnctx){
  BIGNUM *bx = BN_CTX_get(bnctx);
  BIGNUM *by = BN_CTX_get(bnctx);
  bail(bx && by && BN_bin2bn(RAW(x), LENGTH(x), bx) && BN_bin2bn(RAW(y), LENGTH(y), by));
  buf[0] = POINT_CONVERSION_UNCOMPRESSED;
  if(BN_bn2binpad(bx, buf + 1, keysize) < 0 || BN_bn2binpad(by, buf + 1 + keysize, keysize) < 0)
    Rf_error("Failed to construct EC key. Perhaps invalid point or curve.");
}

static EVP_PKEY *ec_key_fromdata(int nid, SEXP x, SEXP y, SEXP d){
  int keysize = nid_keysize(nid);
  unsigned char point[1 + 2 * 66];
  OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
  BN_CTX *bnctx = BN_CTX_new();
  bail(bld && bnctx);
  BN_CTX_start(bnctx);
  ec_point_encode(point, keysize, x, y, bnctx);
  bail(OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2sn(nid), 0));
  bail(OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, point, 1 + 2 * keysize));
  if(d != R_NilValue)
    push_bignum(bld, bnctx, OSSL_PKEY_PARAM_PRIV_KEY, d);
  EVP_PKEY *pkey = pkey_fromdata("EC", d != R_NilValue ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, bld, bnctx);
  if(!pkey){
    ERR_clear_error();
    Rf_error("Failed to construct EC key. Perhaps invalid point or curve.");
  }
  return pkey;
}

static SEXP ec_decompose(EVP_PKEY *pkey, int private){
  char curve[64];
  bail(EVP_PKEY_get_group_name(pkey, curve, sizeof(curve), NULL));
  int nid = OBJ_sn2nid(curve);
  int keysize = nid_keysize(nid);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, private ? 4 : 3));
  SET_VECTOR_ELT(res, 0, Rf_mkString(my_nid2nist(nid)));
  SET_VECTOR_ELT(res, 1, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_EC_PUB_X, keysize));
  SET_VECTOR_ELT(res, 2, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, keysize));
  if(private)
    SET_VECTOR_ELT(res, 3, pkey_get_bignum(pkey, OSSL_PKEY_PARAM_PRIV_KEY, keysize));
  EVP_PKEY_free(pkey);
  UNPROTECT(1);
  return res;
}
#endif

SEXP R_ecdsa_pubkey_build(SEXP x, SEXP y, SEXP nist){
#ifndef OPENSSL_NO_EC
  int nid = my_nist2nid(CHAR(STRING_ELT(nist, 0)));
  bail(nid);
#ifdef HAS_OPENSSL3_API
  return pkey_to_der(ec_key_fromdata(nid, x, y, R_NilValue), 0);
#else
  EC_KEY *pubkey = EC_KEY_new_by_curve_name(nid);
  EC_KEY_set_asn1_flag(pubkey, OPENSSL_EC_NAMED_CURVE);
  if(!EC_KEY_set_public_key_affine_coordinates(pubkey, new_bignum_from_r(x), new_bignum_from_r(y)))
    Rf_error("Failed to construct EC key. Perhaps invalid point or curve.");
  unsigned char *buf = NULL;
  int len = i2d_EC_PUBKEY(pubkey, &buf);
  bail(len);
  EC_KEY_free(pubkey);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#endif
#else //OPENSSL_NO_EC
  Rf_error("OpenSSL has been configured without EC support");
#endif //OPENSSL_NO_EC
}

SEXP R_ecdsa_key_build(SEXP x, SEXP y, SEXP d, SEXP nist){
#ifndef OPENSSL_NO_EC
  int nid = my_nist2nid(CHAR(STRING_ELT(nist, 0)));
  bail(nid);
#ifdef HAS_OPENSSL3_API
  return pkey_to_der(ec_key_fromdata(nid, x, y, d), 1);
#else
  EC_KEY *key = EC_KEY_new_by_curve_name(nid);
  EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
  if(!EC_KEY_set_public_key_affine_coordinates(key, new_bignum_from_r(x), new_bignum_from_r(y)))
    Rf_error("Failed to construct EC key. Perhaps invalid point or curve.");
  EC_KEY_set_private_key(key, new_bignum_from_r(d));
  unsigned char *buf = NULL;
  int len = i2d_ECPrivateKey(key, &buf);
  bail(len);
  EC_KEY_free(key);
  SEXP res = Rf_allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
#endif
#else //OPENSSL_NO_EC
  Rf_error("OpenSSL has been configured without EC support");
#endif //OPENSSL_NO_EC
}

SEXP R_ecdsa_pubkey_decompose(SEXP input){
#ifndef OPENSSL_NO_EC
#ifdef HAS_OPENSSL3_API
  return ec_decompose(pkey_from_der(input, EVP_PKEY_EC, 0), 0);
#else
  const unsigned char *ptr = RAW(input);
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &ptr, LENGTH(input));
  bail(!!pkey);
  EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
  const EC_POINT *pubkey = EC_KEY_get0_public_key(ec);
  const EC_GROUP *group = EC_KEY_get0_group(ec);
  int nid = EC_GROUP_get_curve_name(group);
  int keysize = nid_keysize(nid);
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  bail(EC_POINT_get_affine_coordinates_GFp(group, pubkey, x, y, ctx));
  BN_CTX_free(ctx);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 3));
  SET_VECTOR_ELT(res, 0, Rf_mkString(my_nid2nist(nid)));
  SET_VECTOR_ELT(res, 1, bignum_to_r_size(x, keysize));
  SET_VECTOR_ELT(res, 2, bignum_to_r_size(y, keysize));
  BN_free(x);
  BN_free(y);
  EVP_PKEY_free(pkey);
  UNPROTECT(1);
  return res;
#endif
#else //OPENSSL_NO_EC
  Rf_error("OpenSSL has been configured without EC support");
#endif //OPENSSL_NO_EC
}

SEXP R_ecdsa_priv_decompose(SEXP input){
#ifndef OPENSSL_NO_EC
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);
#ifdef HAS_OPENSSL3_API
  if(EVP_PKEY_base_id(pkey) != EVP_PKEY_EC){
    EVP_PKEY_free(pkey);
    Rf_error("Unexpected key type");
  }
  return ec_decompose(pkey, 1);
#else
  EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
  const EC_POINT *pubkey = EC_KEY_get0_public_key(ec);
  const EC_GROUP *group = EC_KEY_get0_group(ec);
  int nid = EC_GROUP_get_curve_name(group);
  int keysize = nid_keysize(nid);
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  BIGNUM *z = (BIGNUM*) EC_KEY_get0_private_key(ec);
  BN_CTX *ctx = BN_CTX_new();
  bail(EC_POINT_get_affine_coordinates_GFp(group, pubkey, x, y, ctx));
  BN_CTX_free(ctx);
  SEXP res = PROTECT(Rf_allocVector(VECSXP, 4));
  SET_VECTOR_ELT(res, 0, Rf_mkString(my_nid2nist(nid)));
  SET_VECTOR_ELT(res, 1, bignum_to_r_size(x, keysize));
  SET_VECTOR_ELT(res, 2, bignum_to_r_size(y, keysize));
  SET_VECTOR_ELT(res, 3, bignum_to_r_size(z, keysize));
  BN_free(x);
  BN_free(y);
  EVP_PKEY_free(pkey);
  UNPROTECT(1);
  return res;
#endif
#else //OPENSSL_NO_EC
  Rf_error("OpenSSL has been configured without EC support");
#endif //OPENSSL_NO_EC
}
