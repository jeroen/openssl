#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include "utils.h"

BIGNUM *r2bignum(SEXP x){
  if(!inherits(x, "bignum"))
    error("Argument is not valid bignum");
  BIGNUM *val = BN_bin2bn(RAW(x), LENGTH(x), NULL);
  bail(val != NULL);
  return val;
}

SEXP bignum2r(const BIGNUM *val){
  SEXP out = PROTECT(allocVector(RAWSXP, BN_num_bytes(val)));
  bail(BN_bn2bin(val, RAW(out)) >= 0);
  setAttrib(out, R_ClassSymbol, mkString("bignum"));
  UNPROTECT(1);
  return out;
}

SEXP R_parse_bignum(SEXP x, SEXP hex){
  BIGNUM *val = BN_new();
  if(TYPEOF(x) == RAWSXP){
    bail(NULL != BN_bin2bn(RAW(x), LENGTH(x), val));
  } else if(asLogical(hex)){
    bail(BN_hex2bn(&val, CHAR(STRING_ELT(x, 0))));
  } else {
    bail(BN_dec2bn(&val, CHAR(STRING_ELT(x, 0))));
  }
  SEXP res = bignum2r(val);
  BN_free(val);
  return res;
}

SEXP R_bignum_as_character(SEXP x, SEXP hex){
  BIGNUM *val = r2bignum(x);
  char *str;
  if(asLogical(hex)){
    bail(!!(str = BN_bn2hex(val)));
  } else {
    bail(!!(str = BN_bn2dec(val)));
  }
  SEXP res = mkString(str);
  OPENSSL_free(str);
  BN_free(val);
  return res;
}

SEXP R_bignum_as_integer(SEXP x){
  BIGNUM *val = r2bignum(x);
  int res = BN_div_word(val, (BN_ULONG) INT_MAX + 1);
  return ScalarInteger(BN_num_bits(val) ? NA_INTEGER : res);
}

SEXP R_bignum_add(SEXP x, SEXP y){
  BIGNUM *val1 = r2bignum(x);
  BIGNUM *val2 = r2bignum(y);
  BIGNUM *out = BN_new();
  bail(BN_add(out, val1, val2));
  SEXP res = bignum2r(out);
  BN_free(val1);
  BN_free(val2);
  BN_free(out);
  return res;
}

SEXP R_bignum_subtract(SEXP x, SEXP y){
  BIGNUM *val1 = r2bignum(x);
  BIGNUM *val2 = r2bignum(y);
  BIGNUM *out = BN_new();
  bail(BN_sub(out, val1, val2));
  SEXP res = bignum2r(out);
  BN_free(val1);
  BN_free(val2);
  BN_free(out);
  return res;
}

SEXP R_bignum_multiply(SEXP x, SEXP y){
  BIGNUM *val1 = r2bignum(x);
  BIGNUM *val2 = r2bignum(y);
  BIGNUM *out = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  bail(BN_mul(out, val1, val2, ctx));
  SEXP res = bignum2r(out);
  BN_free(val1);
  BN_free(val2);
  BN_free(out);
  BN_CTX_free(ctx);
  return res;
}

SEXP R_bignum_devide(SEXP x, SEXP y){
  BIGNUM *val1 = r2bignum(x);
  BIGNUM *val2 = r2bignum(y);
  BIGNUM *out = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  bail(BN_div(out, NULL, val1, val2, ctx));
  SEXP res = bignum2r(out);
  BN_free(val1);
  BN_free(val2);
  BN_free(out);
  BN_CTX_free(ctx);
  return res;
}

SEXP R_bignum_mod(SEXP x, SEXP y){
  BIGNUM *val1 = r2bignum(x);
  BIGNUM *val2 = r2bignum(y);
  BIGNUM *out = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  bail(BN_mod(out, val1, val2, ctx));
  SEXP res = bignum2r(out);
  BN_free(val1);
  BN_free(val2);
  BN_free(out);
  BN_CTX_free(ctx);
  return res;
}

SEXP R_bignum_exp(SEXP x, SEXP y){
  BIGNUM *val1 = r2bignum(x);
  BIGNUM *val2 = r2bignum(y);
  BIGNUM *out = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  bail(BN_exp(out, val1, val2, ctx));
  SEXP res = bignum2r(out);
  BN_free(val1);
  BN_free(val2);
  BN_free(out);
  BN_CTX_free(ctx);
  return res;
}

SEXP R_bignum_mod_exp(SEXP x, SEXP y, SEXP m){
  BIGNUM *val1 = r2bignum(x);
  BIGNUM *val2 = r2bignum(y);
  BIGNUM *val3 = r2bignum(m);
  BIGNUM *out = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  bail(BN_mod_exp(out, val1, val2, val3, ctx));
  BN_free(val1);
  BN_free(val2);
  BN_free(val3);
  SEXP res = bignum2r(out);
  BN_free(out);
  BN_CTX_free(ctx);
  return res;
}

SEXP R_bignum_mod_inv(SEXP a, SEXP n){
  BIGNUM *val1 = r2bignum(a);
  BIGNUM *val2 = r2bignum(n);
  BIGNUM *out = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  bail(!!BN_mod_inverse(out, val1, val2, ctx));
  BN_free(val1);
  BN_free(val2);
  SEXP res = bignum2r(out);
  BN_free(out);
  BN_CTX_free(ctx);
  return res;
}

SEXP R_bignum_compare(SEXP x, SEXP y){
  BIGNUM *val1 = r2bignum(x);
  BIGNUM *val2 = r2bignum(y);
  int out = BN_cmp(val1, val2);
  BN_free(val1);
  BN_free(val2);
  return ScalarInteger(out);
}

SEXP R_bignum_bits(SEXP x){
  BIGNUM *num = r2bignum(x);
  return ScalarInteger(BN_num_bits(num));
}
