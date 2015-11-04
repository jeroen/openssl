#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <openssl/pem.h>
#include <openssl/bn.h>

SEXP R_pubkey_type(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PUBKEY_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);
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

SEXP R_ec_decompose(SEXP bin){
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
