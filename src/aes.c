#include <R.h>
#include <Rinternals.h>
#include "apple.h"
#include "utils.h"
#include <openssl/evp.h>

/*
 * Adapted from example at: https://www.openssl.org/docs/crypto/EVP_EncryptInit.html
 */

const EVP_CIPHER* get_cipher(int length){
  switch(length){
  case 16:
    return EVP_aes_128_cbc();
  case 24:
    return EVP_aes_192_cbc();
  case 32:
    return EVP_aes_256_cbc();
  }
  error("Invalid key length: %d", length);
}

SEXP R_aes_cbc(SEXP x, SEXP key, SEXP iv, SEXP encrypt) {
  int strength = LENGTH(key);
  if(strength != 16 && strength != 24 && strength != 32)
    error("key must be of length 16 (aes-128), 24 (aes-192) or 32 (aes-256)");

  if(LENGTH(iv) != 16)
    error("aes requires an iv of length 16");

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  bail(EVP_CipherInit_ex(ctx, get_cipher(strength), NULL, RAW(key), RAW(iv), asLogical(encrypt)));

  int blocksize = EVP_CIPHER_CTX_block_size(ctx);
  int remainder = LENGTH(x) % blocksize;
  int outlen = LENGTH(x) + blocksize - remainder;
  unsigned char *buf = OPENSSL_malloc(outlen);
  unsigned char *cur = buf;

  int tmp;
  bail(EVP_CipherUpdate(ctx, cur, &tmp, RAW(x), LENGTH(x)));
  cur += tmp;

  bail(EVP_CipherFinal_ex(ctx, cur, &tmp));
  cur += tmp;

  int total = cur - buf;
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);
  SEXP out = allocVector(RAWSXP, total);
  memcpy(RAW(out), buf, total);
  OPENSSL_free(buf);
  return out;
}
