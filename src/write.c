#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <openssl/pem.h>

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
  SEXP res = PROTECT(allocVector(STRSXP, 1));
  SET_STRING_ELT(res, 0, mkCharLen(buf, len));
  UNPROTECT(1);
  return res;
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
  SEXP res = PROTECT(allocVector(STRSXP, 1));
  SET_STRING_ELT(res, 0, mkCharLen(buf, len));
  UNPROTECT(1);
  return res;
}
