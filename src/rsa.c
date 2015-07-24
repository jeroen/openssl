#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include <openssl/pem.h>
#include <openssl/bn.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

void raise_error();
void bail(int out);

int password_cb(char *buf, int max_size, int rwflag, void *ctx){
  if(!ctx)
    error("No password callback supplied.");

  SEXP cb = (SEXP) ctx;
  int len;

  /* case where password is a hardcoded string */
  if(isString(cb)){
    len = LENGTH(STRING_ELT(cb, 0));
    len = MIN(len, max_size);
    memcpy(buf, CHAR(STRING_ELT(cb, 0)), len);
    return len;
  }

  /* case where password is an R function */
  if(isFunction(cb)){
    int err;
    SEXP call = PROTECT(LCONS(cb, LCONS(mkString("Please enter private key passphrase: "), R_NilValue)));
    SEXP res = PROTECT(R_tryEval(call, R_GlobalEnv, &err));
    if(err || !isString(res)){
      UNPROTECT(2);
      error("Password callback did not return a string value");
    }
    len = LENGTH(STRING_ELT(res, 0));
    len = MIN(len, max_size);
    memcpy(buf, CHAR(STRING_ELT(res, 0)), len);
    UNPROTECT(2);
    return len;
  }
  error("Callback must be string or function");
}

SEXP R_write_pkcs8(RSA *rsa){
  //Rprintf("Public key: d: %d, e: %d, n:%d, p:%p, q:%d\n", rsa->d, rsa->e, rsa->n, rsa->p, rsa->q);
  int len = i2d_RSA_PUBKEY(rsa, NULL);
  bail(len);
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  setAttrib(res, R_ClassSymbol, mkString("rsa.pubkey"));
  UNPROTECT(1);
  unsigned char *ptr = RAW(res);
  bail(i2d_RSA_PUBKEY(rsa, &(ptr)));
  return res;
}

SEXP R_write_rsa_private(RSA *rsa){
  //Rprintf("Private key: d: %d, e: %d, n:%d, p:%p, q:%d\n", rsa->d, rsa->e, rsa->n, rsa->p, rsa->q);
  int len = i2d_RSAPrivateKey(rsa, NULL);
  bail(len);
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  setAttrib(res, R_ClassSymbol, mkString("rsa.private"));
  UNPROTECT(1);
  unsigned char *ptr = RAW(res);
  bail(i2d_RSAPrivateKey(rsa, &(ptr)));
  return res;
}

SEXP R_priv2pub(SEXP bin){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(bin)));
  return R_write_pkcs8(rsa);
}

SEXP R_parse_pkcs1(SEXP input, SEXP type){
  RSA *rsa = RSA_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  bail(!!PEM_read_bio_RSAPublicKey(mem, &rsa, password_cb, NULL));
  bail(EVP_PKEY_assign_RSA(EVP_PKEY_new(), rsa));
  return R_write_pkcs8(rsa);
}

SEXP R_parse_pkcs8(SEXP input){
  RSA *rsa = RSA_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  bail(!!PEM_read_bio_RSA_PUBKEY(mem, &rsa, password_cb, NULL));
  bail(EVP_PKEY_assign_RSA(EVP_PKEY_new(), rsa));
  return R_write_pkcs8(rsa);
}

SEXP R_parse_rsa_private(SEXP input, SEXP password){
  EVP_PKEY *key = EVP_PKEY_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  bail(!!PEM_read_bio_PrivateKey(mem, &key, password_cb, password));
  RSA *rsa = EVP_PKEY_get1_RSA(key);
  return R_write_rsa_private(rsa);
}

SEXP R_rsa_build(SEXP expdata, SEXP moddata){
  RSA *rsa = RSA_new();
  rsa->e = BN_new();
  rsa->n = BN_new();
  bail(!!BN_bin2bn(RAW(expdata), LENGTH(expdata), rsa->e));
  bail(!!BN_bin2bn(RAW(moddata), LENGTH(moddata), rsa->n));
  return R_write_pkcs8(rsa);
}

/* encryption */

SEXP R_rsa_encrypt(SEXP data, SEXP keydata) {
  static unsigned char* buf[8192];
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(keydata);
  bail(!!d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(keydata)));
  int len = RSA_public_encrypt(LENGTH(data), RAW(data), (unsigned char*) buf, rsa, RSA_PKCS1_PADDING);
  bail(len > 0);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  return res;
}

SEXP R_rsa_decrypt(SEXP data, SEXP keydata){
  static unsigned char* buf[8192];
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(keydata);
  bail(!!d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(keydata)));
  int len = RSA_private_decrypt(LENGTH(data), RAW(data), (unsigned char*) buf, rsa, RSA_PKCS1_PADDING);
  bail(len > 0);
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  return res;
}

/* sign and verify signatures */

int gettype(const char *str){
  if (!strcmp(str, "md5")) {
    return NID_md5;
  } else if (!strcmp(str, "sha1")) {
    return NID_sha1;
  } else if (!strcmp(str, "sha256")) {
    return NID_sha256;
  }
  error("Invalid hash type: %s", str);
}

SEXP R_rsa_sign(SEXP hashdata, SEXP type, SEXP keydata){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(keydata);
  bail(!!d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(keydata)));
  unsigned char* buf[RSA_size(rsa)];
  unsigned int len;
  int hashtype = gettype(CHAR(STRING_ELT(type, 0)));
  bail(!!RSA_sign(hashtype, RAW(hashdata), LENGTH(hashdata), (unsigned char *) buf, &len, rsa));
  SEXP res = allocVector(RAWSXP, len);
  memcpy(RAW(res), buf, len);
  return res;
}

SEXP R_rsa_verify(SEXP hashdata, SEXP sigdata, SEXP type, SEXP keydata){
  RSA *rsa = RSA_new();
  const unsigned char *ptr = RAW(keydata);
  bail(!!d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(keydata)));
  int hashtype = gettype(CHAR(STRING_ELT(type, 0)));
  bail(!!RSA_verify(hashtype, RAW(hashdata), LENGTH(hashdata), RAW(sigdata), LENGTH(sigdata), rsa));
  return ScalarLogical(1);
}

/* certificate stuff */
SEXP R_parse_x509(SEXP input){
  X509 *cert = X509_new();
  BIO *mem = BIO_new_mem_buf(RAW(input), LENGTH(input));
  bail(!!PEM_read_bio_X509(mem, &cert, password_cb, NULL));
  unsigned char *buf = NULL;
  int len = i2d_X509(cert, &buf);
  bail(len > 0);
  SEXP res = PROTECT(allocVector(RAWSXP, len));
  setAttrib(res, R_ClassSymbol, mkString("x509.cert"));
  memcpy(RAW(res), buf, len);
  UNPROTECT(1);
  free(buf);
  return res;
}

SEXP R_cert2pub(SEXP bin){
  X509 *cert = X509_new();
  const unsigned char *ptr = RAW(bin);
  bail(!!d2i_X509(&cert, &ptr, LENGTH(bin)));
  EVP_PKEY *key = X509_get_pubkey(cert);
  if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA)
    error("Key is not RSA key");
  RSA *rsa = EVP_PKEY_get1_RSA(key);
  return R_write_pkcs8(rsa);
}

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
