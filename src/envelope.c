#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include "utils.h"

SEXP R_envelope_encrypt(SEXP data, SEXP pubkey) {
  /* Input arrays because OpenSSL supports multi-key encryption */
  const unsigned char *ptr = RAW(pubkey);
  EVP_PKEY *pkey[1];
  pkey[0] = d2i_PUBKEY(NULL, &ptr, LENGTH(pubkey));
  bail(!!pkey[0]);

  /* Encryption context */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  bail(!!ctx);

  /* Secret key arrays */
  int keysize = EVP_PKEY_size(pkey[0]);
  unsigned char buf[keysize];
  unsigned char *ek[1];
  int ekl[1];
  ek[0] = buf;

  /* Alloc buffers and init */
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();
  int ivlen = EVP_CIPHER_iv_length(cipher);
  unsigned char iv[ivlen];
  bail(EVP_SealInit(ctx, cipher, ek, ekl, iv, pkey, 1));

  /* This is an overestimate */
  int len1;
  unsigned char *out = malloc(LENGTH(data) + 16);
  bail(EVP_SealUpdate(ctx, out, &len1, RAW(data), LENGTH(data)));

  /* Finalize and cleanup */
  int len2;
  bail(EVP_SealFinal(ctx, out + len1, &len2));
  EVP_PKEY_free(pkey[0]);
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);

  /* Create output vector */
  SEXP res = PROTECT(allocVector(VECSXP, 3));
  SET_VECTOR_ELT(res, 0, allocVector(RAWSXP, ivlen));
  SET_VECTOR_ELT(res, 1, allocVector(RAWSXP, ekl[0]));
  SET_VECTOR_ELT(res, 2, allocVector(RAWSXP, len1 + len2));
  memcpy(RAW(VECTOR_ELT(res, 0)), iv, ivlen);
  memcpy(RAW(VECTOR_ELT(res, 1)), ek[0], ekl[0]);
  memcpy(RAW(VECTOR_ELT(res, 2)), out, len1 + len2);
  free(out);
  UNPROTECT(1);
  return res;
}

SEXP R_envelope_decrypt(SEXP data, SEXP iv, SEXP session, SEXP key) {
  /* Decryption is done with a single key */
  BIO *mem = BIO_new_mem_buf(RAW(key), LENGTH(key));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);

  /* Encryption context */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  bail(!!ctx);

  /* Verify key size */
  if(LENGTH(session) != EVP_PKEY_size(pkey))
    error("Invalid Session key, must be %d bytes", EVP_PKEY_size(pkey));


  /* Alloc buffers and init */
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();
  int ivlen = EVP_CIPHER_iv_length(cipher);
  if(ivlen != LENGTH(iv))
    error("Invalid IV, must be %d bytes", ivlen);
  bail(EVP_OpenInit(ctx, EVP_aes_256_cbc(), RAW(session), LENGTH(session), RAW(iv), pkey));

  /* This is an overestimate */
  int len1 = 0;
  unsigned char *out = malloc(LENGTH(data) + 16);
  bail(EVP_OpenUpdate(ctx, out, &len1, RAW(data), LENGTH(data)));

  /* Finalize and cleanup */
  int len2 = 0;
  bail(EVP_OpenFinal(ctx, out + len1, &len2));
  EVP_PKEY_free(pkey);
  EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);

  /* Create RAW vector */
  SEXP res = allocVector(RAWSXP, len1 + len2);
  memcpy(RAW(res), out,  len1 + len2);
  free(out);
  return res;
}
