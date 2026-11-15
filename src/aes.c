#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "utils.h"

/*
 * Adapted from example at: https://www.openssl.org/docs/crypto/EVP_EncryptInit.html
 */

SEXP R_aes_any(SEXP x, SEXP key, SEXP iv, SEXP encrypt, SEXP cipher, SEXP tag, SEXP aad) {
  int strength = LENGTH(key);
  if(strength != 16 && strength != 24 && strength != 32)
    Rf_error("key must be of length 16 (aes-128), 24 (aes-192) or 32 (aes-256)");

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *cph = EVP_get_cipherbyname(CHAR(STRING_ELT(cipher, 0)));
  if(!cph)
    Rf_error("Invalid cipher: %s", CHAR(STRING_ELT(cipher, 0)));

  int gcm = EVP_CIPHER_mode(cph) == EVP_CIPH_GCM_MODE;
  if(gcm){
    if(LENGTH(iv) < 1){
      Rf_error("aes-gcm requires a non-empty iv");
    }
    //GCM mode has shorter IV from the others
    bail(EVP_CipherInit_ex(ctx, cph, NULL, NULL, NULL, Rf_asLogical(encrypt)));
    bail(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, LENGTH(iv), NULL));
  } else if(LENGTH(iv) != 16){
    Rf_error("aes requires an iv of length 16");
  }
  bail(EVP_CipherInit_ex(ctx, gcm ? NULL : cph, NULL, RAW(key), RAW(iv), Rf_asLogical(encrypt)));

  int blocksize = EVP_CIPHER_CTX_block_size(ctx);
  int remainder = LENGTH(x) % blocksize;
  int outlen = LENGTH(x) + blocksize - remainder;
  unsigned char *buf = OPENSSL_malloc(outlen);
  unsigned char *cur = buf;

  int tmp;
  if(gcm && Rf_length(aad))
    bail(EVP_CipherUpdate(ctx, NULL, &tmp, RAW(aad), LENGTH(aad)));
  bail(EVP_CipherUpdate(ctx, cur, &tmp, RAW(x), LENGTH(x)));
  cur += tmp;

  if(gcm && !Rf_asLogical(encrypt) && Rf_length(tag))
    bail(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, LENGTH(tag), RAW(tag)));
  //in GCM mode, res indicates if the security tag was verified successfully.
  int res = EVP_CipherFinal_ex(ctx, cur, &tmp);
  if(!gcm)
    bail(res);
  if(gcm && !Rf_asLogical(encrypt) && Rf_length(tag) && res != 1){
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(buf);
    Rf_error("aes-gcm authentication failed: data or tag has been modified");
  }
  cur += tmp;

  int total = cur - buf;
  SEXP out = PROTECT(Rf_allocVector(RAWSXP, total));
  memcpy(RAW(out), buf, total);
  OPENSSL_free(buf);
  if(gcm && Rf_asLogical(encrypt)){
    SEXP tagout = PROTECT(Rf_allocVector(RAWSXP, 16));
    bail(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, RAW(tagout)));
    Rf_setAttrib(out, Rf_install("tag"), tagout);
    UNPROTECT(1);
  }
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);
  UNPROTECT(1);
  return out;
}

SEXP R_aes_keywrap(SEXP x, SEXP key, SEXP encrypt) {
  const EVP_CIPHER *cph = NULL;
  switch(LENGTH(key)){
  case 16: cph = EVP_aes_128_wrap(); break;
  case 24: cph = EVP_aes_192_wrap(); break;
  case 32: cph = EVP_aes_256_wrap(); break;
  default: Rf_error("key must be of length 16 (aes-128), 24 (aes-192) or 32 (aes-256)");
  }
  int wrap = Rf_asLogical(encrypt);
  if(LENGTH(x) % 8 || LENGTH(x) < (wrap ? 16 : 24))
    Rf_error("data must be a multiple of 8 bytes with a minimum of %d", wrap ? 16 : 24);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
  bail(EVP_CipherInit_ex(ctx, cph, NULL, RAW(key), NULL, wrap));
  unsigned char *buf = OPENSSL_malloc(LENGTH(x) + 16);
  int len = 0, tmp = 0;
  int ok = EVP_CipherUpdate(ctx, buf, &len, RAW(x), LENGTH(x)) &&
    EVP_CipherFinal_ex(ctx, buf + len, &tmp);
  EVP_CIPHER_CTX_free(ctx);
  if(!ok){
    OPENSSL_free(buf);
    Rf_error(wrap ? "aes key wrap failed" : "aes key unwrap failed: wrong key or data has been modified");
  }
  SEXP out = Rf_allocVector(RAWSXP, len + tmp);
  memcpy(RAW(out), buf, len + tmp);
  OPENSSL_free(buf);
  return out;
}
