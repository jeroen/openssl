#include <Rinternals.h>
#include <openssl/pem.h>
#include "utils.h"

SEXP R_pem_write_key(SEXP input, SEXP password){
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);
  BIO *out = BIO_new(BIO_s_mem());
  if(!isNull(password) && LENGTH(STRING_ELT(password, 0))){
    char *pass = (char*) CHAR(STRING_ELT(password, 0));
    PEM_write_bio_PrivateKey(out, pkey, EVP_des_ede3_cbc(), NULL, 0, NULL, pass);
  } else {
    PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL);
  }
  int bufsize = 8192;
  char buf[bufsize];
  int len = BIO_read(out, buf, bufsize);
  BIO_free(out);
  bail(len);
  return ScalarString(mkCharLen(buf, len));
}

/* legacy format but still used by old ssh clients */
SEXP R_pem_write_pkcs1_privkey(SEXP keydata, SEXP password){
  const unsigned char *ptr = RAW(keydata);
  RSA *rsa = d2i_RSAPrivateKey(NULL, &ptr, LENGTH(keydata));
  bail(!!rsa);
  BIO *out = BIO_new(BIO_s_mem());
  if(!isNull(password) && LENGTH(STRING_ELT(password, 0))){
    char *pass = (char*) CHAR(STRING_ELT(password, 0));
    PEM_write_bio_RSAPrivateKey(out, rsa, EVP_des_ede3_cbc(), NULL, 0, NULL, pass);
  } else {
    PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL);
  }
  int bufsize = 8192;
  char buf[bufsize];
  int len = BIO_read(out, buf, bufsize);
  BIO_free(out);
  bail(len);
  return ScalarString(mkCharLen(buf, len));
}

/* legacy format but still used by old ssh clients */
SEXP R_pem_write_pkcs1_pubkey(SEXP keydata){
  const unsigned char *ptr = RAW(keydata);
  RSA *rsa = d2i_RSA_PUBKEY(NULL, &ptr, LENGTH(keydata));
  bail(!!rsa);
  BIO *out = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPublicKey(out, rsa);
  int bufsize = 8192;
  char buf[bufsize];
  int len = BIO_read(out, buf, bufsize);
  BIO_free(out);
  bail(len);
  return ScalarString(mkCharLen(buf, len));
}

SEXP R_pem_write_pubkey(SEXP input){
  const unsigned char *ptr = RAW(input);
  EVP_PKEY *pkey = d2i_PUBKEY(NULL, &ptr, LENGTH(input));
  bail(!!pkey);
  BIO *out = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(out, pkey);
  int bufsize = 8192;
  char buf[bufsize];
  int len = BIO_read(out, buf, bufsize);
  BIO_free(out);
  bail(len);
  return ScalarString(mkCharLen(buf, len));
}

SEXP R_pem_write_cert(SEXP input){
  X509 *cert = X509_new();
  const unsigned char *ptr = RAW(input);
  bail(!!d2i_X509(&cert, &ptr, LENGTH(input)));
  BIO *out = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(out, cert);
  int bufsize = 100000;
  char buf[bufsize];
  int len = BIO_read(out, buf, bufsize);
  BIO_free(out);
  bail(len);
  return ScalarString(mkCharLen(buf, len));
}
