/* Adapted from https://github.com/openssl/openssl/blob/master/apps/pkcs7.c
 */

#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include "utils.h"

SEXP R_parse_pem_pkcs7(SEXP input){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  PKCS7 *p7 = PEM_read_bio_PKCS7(mem, NULL, password_cb, NULL);
  unsigned char *buf = NULL;
  int len = i2d_PKCS7(p7, &buf);
  PKCS7_free(p7);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_write_pkcs7(SEXP cadata){
  PKCS7 *p7 = PKCS7_new();
  p7->type = OBJ_nid2obj(NID_pkcs7_signed);
  p7->d.sign = PKCS7_SIGNED_new();
  p7->d.sign->contents->type = OBJ_nid2obj(NID_pkcs7_data);
  p7->d.sign->cert = sk_X509_new_null();
  for(int i = 0; i < Rf_length(cadata); i++){
    const unsigned char *ptr = RAW(VECTOR_ELT(cadata, i));
    X509 * crt = d2i_X509(NULL, &ptr, Rf_length(VECTOR_ELT(cadata, i)));
    bail(!!crt);
    bail(sk_X509_push(p7->d.sign->cert, crt));
  }
  unsigned char *buf = NULL;
  int len = i2d_PKCS7(p7, &buf);
  bail(len);
  PKCS7_free(p7);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_parse_der_pkcs7(SEXP input){
  const unsigned char *ptr = RAW(input);
  PKCS7 *p7 = d2i_PKCS7(NULL, &ptr, LENGTH(input));
  bail(!!p7);

  STACK_OF(X509) *certs = NULL;
  STACK_OF(X509_CRL) *crls = NULL;

  int p7type = OBJ_obj2nid(p7->type);
  if(p7type == NID_pkcs7_signed){
    if (p7->d.sign != NULL) {
      certs = p7->d.sign->cert;
      crls = p7->d.sign->crl;
    }
  } else if(p7type == NID_pkcs7_signedAndEnveloped){
    if (p7->d.signed_and_enveloped != NULL) {
      certs = p7->d.signed_and_enveloped->cert;
      crls = p7->d.signed_and_enveloped->crl;
    }
  } else {
    Rf_errorcall(R_NilValue, "Unsupported P7 type: %d\n", p7type);
  }

  unsigned char *buf = NULL;
  int len = 0;
  SEXP out = PROTECT(allocVector(VECSXP, 2));

  if (certs != NULL) {
    int n = sk_X509_num(certs);
    SEXP bundle = PROTECT(allocVector(VECSXP, n));
    for(int i = 0; i < n; i++){
      X509 *x = sk_X509_value(certs, i);
      len = i2d_X509(x, &buf);
      bail(len);
      SET_VECTOR_ELT(bundle, i, allocVector(RAWSXP, len));
      memcpy(RAW(VECTOR_ELT(bundle, i)), buf, len);
      OPENSSL_free(buf);
      buf = NULL;
    }
    SET_VECTOR_ELT(out, 0, bundle);
    UNPROTECT(1);
  }

  if (crls != NULL) {
    int n = sk_X509_CRL_num(crls);
    SEXP bundle = PROTECT(allocVector(VECSXP, n));
    for(int i = 0; i < n; i++){
      X509_CRL *crl = sk_X509_CRL_value(crls, i);
      len = i2d_X509_CRL(crl, &buf);
      bail(len);
      SET_VECTOR_ELT(bundle, i, allocVector(RAWSXP, len));
      memcpy(RAW(VECTOR_ELT(bundle, i)), buf, len);
      OPENSSL_free(buf);
      buf = NULL;
    }
    SET_VECTOR_ELT(out, 1, bundle);
    UNPROTECT(1);
  }
  PKCS7_free(p7);
  UNPROTECT(1);
  return out;
}
