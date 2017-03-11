#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "utils.h"

/*
 * Adapted from example at: https://www.openssl.org/docs/crypto/EVP_EncryptInit.html
 */

SEXP R_aes_any(SEXP x, SEXP key, SEXP iv, SEXP encrypt, SEXP cipher) {
  int strength = LENGTH(key);
  if(strength != 16 && strength != 24 && strength != 32)
    error("key must be of length 16 (aes-128), 24 (aes-192) or 32 (aes-256)");

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *cph = EVP_get_cipherbyname(CHAR(STRING_ELT(cipher, 0)));
  if(!cph)
    Rf_error("Invalid cipher: %s", CHAR(STRING_ELT(cipher, 0)));

#ifdef EVP_CIPH_GCM_MODE //openssl 1.0.0 does not have GCM
  if(EVP_CIPHER_mode(cph) == EVP_CIPH_GCM_MODE){
    if(LENGTH(iv) != 12){
      Rf_error("aes-gcm requires an iv of length 12");
    }
    //GCM mode has shorter IV from the others
    bail(EVP_CipherInit_ex(ctx, cph, NULL, NULL, NULL, asLogical(encrypt)));
    bail(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, LENGTH(iv), NULL));
  } else
#endif //EVP_CIPH_GCM_MODE
  if(LENGTH(iv) != 16){
    Rf_error("aes requires an iv of length 16");
  }
  bail(EVP_CipherInit_ex(ctx, cph, NULL, RAW(key), RAW(iv), asLogical(encrypt)));

  int blocksize = EVP_CIPHER_CTX_block_size(ctx);
  int remainder = LENGTH(x) % blocksize;
  int outlen = LENGTH(x) + blocksize - remainder;
  unsigned char *buf = OPENSSL_malloc(outlen);
  unsigned char *cur = buf;

  int tmp;
  bail(EVP_CipherUpdate(ctx, cur, &tmp, RAW(x), LENGTH(x)));
  cur += tmp;


#ifdef EVP_CIPH_GCM_MODE //openssl 1.0.0
  //in GCM mode, res indicates if the security tag was verified successfully.
  int res = EVP_CipherFinal_ex(ctx, cur, &tmp);
  if(EVP_CIPHER_mode(cph) != EVP_CIPH_GCM_MODE)
    bail(res);
#else
  EVP_CipherFinal_ex(ctx, cur, &tmp);
#endif //EVP_CIPH_GCM_MODE
  cur += tmp;

  int total = cur - buf;
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);
  SEXP out = allocVector(RAWSXP, total);
  memcpy(RAW(out), buf, total);
  OPENSSL_free(buf);
  return out;
}
