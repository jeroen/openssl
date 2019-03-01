#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "utils.h"

SEXP R_base64_encode(SEXP bin, SEXP linebreaks){
  //setup encoder
  BIO *bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem()));

  //No linebreaks
  if(!asLogical(linebreaks))
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  bail(BIO_set_close(bio, BIO_NOCLOSE));
  BIO_write(bio, RAW(bin), LENGTH(bin));
  bail(BIO_flush(bio));

  //Get the output
  BUF_MEM *buf;
  BIO_get_mem_ptr(bio, &buf);

  //return a character vector
  SEXP out = PROTECT(allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, mkCharLen(buf->data, buf->length));
  UNPROTECT(1);

  //Cleanup and return
  BIO_free_all(bio);
  return out;
}

SEXP R_base64_decode(SEXP text){
  int len = LENGTH(STRING_ELT(text, 0));
  BIO *bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new_mem_buf((void*) CHAR(STRING_ELT(text, 0)), len));

  //Assume on linebreaks
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  //binary size is always smaller than base64 msg
  unsigned char *bin = malloc(len);
  int bin_len = BIO_read(bio, bin, len);

  //create raw output vector
  SEXP out = PROTECT(allocVector(RAWSXP, bin_len));
  memcpy(RAW(out), bin, bin_len);
  UNPROTECT(1);

  //cleanup and return
  BIO_free_all(bio);
  free(bin);
  return out;
}
