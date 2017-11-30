#include <stdlib.h>
#include <string.h>
#include <Rinternals.h>
#include <openssl/crypto.h>
#include <openssl/pkcs12.h>
#include "utils.h"

static char *find_friendly_name(PKCS12 *p12);

SEXP R_write_pkcs12(SEXP keydata, SEXP certdata, SEXP cadata, SEXP namedata, SEXP pwdata){
  EVP_PKEY * pkey = NULL;
  X509 * cert = NULL;
  STACK_OF(X509) * ca = sk_X509_new_null();
  char * name = NULL;
  char * pw = NULL;

  //parse private key
  if(Rf_length(keydata)){
    BIO *mem = BIO_new_mem_buf(RAW(keydata), LENGTH(keydata));
    pkey = d2i_PrivateKey_bio(mem, NULL);
    BIO_free(mem);
    bail(!!pkey);
  }

  //parse certificate
  if(Rf_length(certdata)){
    const unsigned char *ptr = RAW(certdata);
    cert = d2i_X509(NULL, &ptr, LENGTH(certdata));
    bail(!!cert);
  }

  //add other certs
  for(int i = 0; i < Rf_length(cadata); i++){
    const unsigned char *ptr = RAW(VECTOR_ELT(cadata, i));
    X509 * crt = d2i_X509(NULL, &ptr, Rf_length(VECTOR_ELT(cadata, i)));
    bail(!!crt);
    sk_X509_push(ca, crt);
  }

  //get name
  if(Rf_length(namedata)){
    name = (char*) CHAR(STRING_ELT(namedata, 0));
  }

  //get password
  if(Rf_length(pwdata)){
    pw = (char*) CHAR(STRING_ELT(pwdata, 0));
  }

  // create the P12
  PKCS12 *p12 = PKCS12_create(pw, name, pkey, cert, ca, 0, 0, 0, 0, 0);
  bail(!!p12);

  //serialize to R
  unsigned char *buf = NULL;
  int len = i2d_PKCS12(p12, &buf);
  bail(len);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  OPENSSL_free(buf);
  return res;
}

SEXP R_parse_pkcs12(SEXP input, SEXP pass){
  const unsigned char *ptr = RAW(input);
  PKCS12 *p12 = d2i_PKCS12(NULL, &ptr, LENGTH(input));
  bail(!!p12);
  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  STACK_OF(X509) *ca = NULL;

  int success = 0;
  int max_size = 200;
  char passwd[max_size];
  if(PKCS12_verify_mac(p12, NULL, 0) || PKCS12_verify_mac(p12, "", 1)){
    success = PKCS12_parse(p12, "", &pkey, &cert, &ca);
  } else {
    password_cb(passwd, max_size, 0, pass);
    if(!PKCS12_verify_mac(p12, passwd, strlen(passwd)))
      Rf_errorcall(R_NilValue, "PKCS12 read failure: invalid password");
    success = PKCS12_parse(p12, passwd, &pkey, &cert, &ca);
  }
  char * friendly_name = find_friendly_name(p12);
  PKCS12_free(p12);
  bail(success);

  unsigned char *buf = NULL;
  int len = 0;
  SEXP res = PROTECT(allocVector(VECSXP, 4));
  if (cert != NULL) {
    len = i2d_X509(cert, &buf);
    X509_free(cert);
    bail(len);
    SET_VECTOR_ELT(res, 0, allocVector(RAWSXP, len));
    memcpy(RAW(VECTOR_ELT(res, 0)), buf, len);
    OPENSSL_free(buf);
    buf = NULL;
  }
  if(pkey != NULL){
    len = i2d_PrivateKey(pkey, &buf);
    EVP_PKEY_free(pkey);
    bail(len);
    SET_VECTOR_ELT(res, 1, allocVector(RAWSXP, len));
    memcpy(RAW(VECTOR_ELT(res, 1)), buf, len);
    OPENSSL_free(buf);
    buf = NULL;
  }
  if(ca && sk_X509_num(ca)){
    int ncerts = sk_X509_num(ca);
    SEXP bundle = PROTECT(allocVector(VECSXP, ncerts));
    for(int i = 0; i < ncerts; i++){
      cert = sk_X509_value(ca, (ncerts - i - 1)); //reverse order to match PEM/SSL
      len = i2d_X509(cert, &buf);
      bail(len);
      SET_VECTOR_ELT(bundle, i, allocVector(RAWSXP, len));
      memcpy(RAW(VECTOR_ELT(bundle, i)), buf, len);
      OPENSSL_free(buf);
      buf = NULL;
    }
    sk_X509_pop_free(ca, X509_free);
    SET_VECTOR_ELT(res, 2, bundle);
    UNPROTECT(1);
  }
  if(friendly_name)
    SET_VECTOR_ELT(res, 3, mkString(friendly_name));
  UNPROTECT(1);
  return res;
}

//https://github.com/openssl/openssl/issues/1796
static char *find_friendly_name(PKCS12 *p12){
  STACK_OF(PKCS7) *safes = PKCS12_unpack_authsafes(p12);
  int n, m;
  char *name = NULL;
  PKCS7 *safe;
  STACK_OF(PKCS12_SAFEBAG) *bags;
  PKCS12_SAFEBAG *bag;

  if ((safes = PKCS12_unpack_authsafes(p12)) == NULL)
    return NULL;

  for (n = 0; n < sk_PKCS7_num(safes) && name == NULL; n++) {
    safe = sk_PKCS7_value(safes, n);
    if (OBJ_obj2nid(safe->type) != NID_pkcs7_data
          || (bags = PKCS12_unpack_p7data(safe)) == NULL)
      continue;

    for (m = 0; m < sk_PKCS12_SAFEBAG_num(bags) && name == NULL; m++) {
      bag = sk_PKCS12_SAFEBAG_value(bags, m);
      name = PKCS12_get_friendlyname(bag);
    }
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
  }

  sk_PKCS7_pop_free(safes, PKCS7_free);

  return name;
}
