#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <openssl/pem.h>
#include <openssl/bn.h>

SEXP R_certinfo(SEXP bin){
  X509 *cert = X509_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_X509(&cert, &ptr, LENGTH(bin)));

  //out list
  int bufsize = 8192;
  char buf[bufsize];
  int len;
  X509_NAME *name;
  BIO *b;
  SEXP out = PROTECT(allocVector(VECSXP, 5));

  //subject name
  name = X509_get_subject_name(cert);
  X509_NAME_oneline(name, buf, bufsize);
  SET_VECTOR_ELT(out, 0, mkString(buf));
  X509_NAME_free(name);

  //issuer name name
  name = X509_get_issuer_name(cert);
  X509_NAME_oneline(name, buf, bufsize);
  SET_VECTOR_ELT(out, 1, mkString(buf));
  X509_NAME_free(name);

  //sign algorithm
  OBJ_obj2txt(buf, sizeof(buf), cert->sig_alg->algorithm, 0);
  SET_VECTOR_ELT(out, 2, mkString(buf));

  //start date
  b = BIO_new(BIO_s_mem());
  bail(ASN1_TIME_print(b, cert->cert_info->validity->notBefore));
  len = BIO_read(b, buf, bufsize);
  bail(len);
  buf[len] = '\0';
  SET_VECTOR_ELT(out, 3, mkString(buf));
  BIO_free(b);

  //expiration date
  b = BIO_new(BIO_s_mem());
  bail(ASN1_TIME_print(b, cert->cert_info->validity->notAfter));
  len = BIO_read(b, buf, bufsize);
  bail(len);
  buf[len] = '\0';
  SET_VECTOR_ELT(out, 4, mkString(buf));
  BIO_free(b);

  //return
  UNPROTECT(1);
  return out;
}

SEXP R_verify_cert(SEXP certdata, SEXP cadata) {
  /* load cert */
  const unsigned char *ptr = RAW(certdata);
  X509 *cert = X509_new();
  X509 *ca = X509_new();
  bail(!!d2i_X509(&cert, &ptr, LENGTH(certdata)));

  /* init ca bundle store */
  X509_STORE *store = X509_STORE_new();
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  X509_STORE_CTX_init(ctx, store, cert, NULL);

  /* cadata is either path to bundle or cert */
  if(isString(cadata)){
    bail(X509_STORE_load_locations(store, CHAR(STRING_ELT(cadata, 0)), NULL));
  } else {
    ptr = RAW(cadata);
    bail(!!d2i_X509(&ca, &ptr, LENGTH(cadata)));
    bail(X509_STORE_add_cert(store, ca));
  }

  if(X509_verify_cert(ctx) < 1)
    stop("Certificate validation failed: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));

  X509_STORE_CTX_free(ctx);
  X509_STORE_free(store);
  X509_free(cert);
  X509_free(ca);
  return ScalarLogical(1);
}
