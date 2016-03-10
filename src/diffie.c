#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include "utils.h"

/***
 * example from: https://wiki.openssl.org/index.php/EVP_Key_Agreement
 *
 *
 */


SEXP R_diffie_hellman(SEXP key, SEXP peerkey){
  BIO *mem = BIO_new_mem_buf(RAW(key), LENGTH(key));
  EVP_PKEY *pkey = d2i_PrivateKey_bio(mem, NULL);
  BIO_free(mem);
  bail(!!pkey);
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  bail(!!ctx);
  const unsigned char *ptr = RAW(peerkey);
  EVP_PKEY *pubkey = d2i_PUBKEY(NULL, &ptr, LENGTH(peerkey));
  bail(!!pubkey);
  bail(EVP_PKEY_derive_init(ctx) > 0);
  bail(EVP_PKEY_derive_set_peer(ctx, pubkey) > 0);

  /* Determine buffer length */
  size_t skeylen = 0;
  bail(EVP_PKEY_derive(ctx, NULL, &skeylen) > 0);
  SEXP out = allocVector(RAWSXP, skeylen);
  bail(EVP_PKEY_derive(ctx, RAW(out), &skeylen) > 0);

  /* cleanup */
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  EVP_PKEY_free(pubkey);
  return out;
}
