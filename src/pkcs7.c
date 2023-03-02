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
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  Rf_setAttrib(res, R_ClassSymbol, Rf_mkString("pkcs7"));
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  UNPROTECT(1);
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
  } else if(p7type == NID_pkcs7_enveloped){
    Rf_errorcall(R_NilValue, "This is an encrypted PKCS7, use pkcs7_decrypt() instead");
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

SEXP R_pkcs7_decrypt(SEXP input, SEXP keydata){
  const unsigned char *ptr = RAW(input);
  PKCS7 *p7 = d2i_PKCS7(NULL, &ptr, LENGTH(input));
  bail(!!p7);
  int p7type = OBJ_obj2nid(p7->type);
  if(p7type != NID_pkcs7_enveloped)
    Rf_error("PKCS7 is not an encrypted message. Try read_pb7()");
  BIO *mem = BIO_new_mem_buf(RAW(keydata), LENGTH(keydata));
  EVP_PKEY * pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);
  BIO *msgbuf = BIO_new(BIO_s_mem());
  bail(PKCS7_decrypt(p7, pkey, NULL, msgbuf, 0));
  int maxsize = 1000000; // I have no idea what is appropriate
  void *buf = malloc(maxsize);
  int len = BIO_read(msgbuf, buf, maxsize);
  bail(len > 0);
  BIO_free(msgbuf);
  SEXP content = allocVector(RAWSXP, len);
  memcpy(RAW(content), buf, len);
  PKCS7_free(p7);
  return content;
}

SEXP R_pkcs7_encrypt(SEXP message, SEXP cert){
  const unsigned char *ptr = RAW(cert);
  X509 *crt = d2i_X509(NULL, &ptr, LENGTH(cert));
  bail(!!crt);
  STACK_OF(X509) *sk = sk_X509_new_null();
  bail(sk_X509_push(sk, crt));
  BIO *bio = BIO_push(BIO_new(BIO_f_buffer()), BIO_new_mem_buf((void*) RAW(message), Rf_length(message)));
  PKCS7 *p7 = PKCS7_encrypt(sk, bio, EVP_des_ede3_cbc(), PKCS7_BINARY);
  bail(!!p7);
  BIO_free(bio);
  sk_X509_free(sk);
  X509_free(crt);
  unsigned char *buf = NULL;
  int len = i2d_PKCS7(p7, &buf);
  bail(len);
  PKCS7_free(p7);
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  Rf_setAttrib(res, R_ClassSymbol, Rf_mkString("pkcs7"));
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  UNPROTECT(1);
  return res;
}
