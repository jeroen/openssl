#include <Rinternals.h>
#include <openssl/pem.h>
#include "utils.h"
#include "compatibility.h"

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
  EVP_PKEY_free(pkey);
  int bufsize = 8192;
  char buf[bufsize];
  int len = BIO_read(out, buf, bufsize);
  BIO_free(out);
  bail(len);
  return ScalarString(mkCharLen(buf, len));
}

/* legacy format but still used by old ssh clients */
SEXP R_pem_write_pkcs1_privkey(SEXP keydata, SEXP password){
  BIO *mem = BIO_new_mem_buf(RAW(keydata), LENGTH(keydata));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);
  BIO *out = BIO_new(BIO_s_mem());
  int type = EVP_PKEY_base_id(pkey);
  char *pass = NULL;
  if(Rf_length(password) && Rf_length(STRING_ELT(password, 0)))
    pass = (char*) CHAR(STRING_ELT(password, 0));
  if(type == EVP_PKEY_RSA){
    RSA *rsa = (RSA*) MY_EVP_PKEY_get0_RSA(pkey);
    if(pass){
      PEM_write_bio_RSAPrivateKey(out, rsa, EVP_des_ede3_cbc(), NULL, 0, NULL, pass);
    } else {
      PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL);
    }
  } else if(type == EVP_PKEY_DSA){
    DSA *dsa = (DSA*) MY_EVP_PKEY_get0_DSA(pkey);
    if(pass){
      PEM_write_bio_DSAPrivateKey(out, dsa, EVP_des_ede3_cbc(), NULL, 0, NULL, pass);
    } else {
      PEM_write_bio_DSAPrivateKey(out, dsa, NULL, NULL, 0, NULL, NULL);
    }
  } else if(type == EVP_PKEY_EC){
    EC_KEY *ec = (EC_KEY*) MY_EVP_PKEY_get0_EC_KEY(pkey);
    if(pass){
      PEM_write_bio_ECPrivateKey(out, ec, EVP_des_ede3_cbc(), NULL, 0, NULL, pass);
    } else {
      PEM_write_bio_ECPrivateKey(out, ec, NULL, NULL, 0, NULL, NULL);
    }
  } else {
    Rf_error("This key type cannot be exported to PKCS1");
  }
  EVP_PKEY_free(pkey);
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
