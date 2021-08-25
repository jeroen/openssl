#include <Rinternals.h>
#include <openssl/err.h>
#include "utils.h"

void raise_error(){
  char buf[8192] = {0};
  BIO *bp = BIO_new(BIO_s_mem());
  ERR_print_errors(bp);
  int len = BIO_read(bp, buf, 8192);
  BIO_free(bp);
  Rf_error("OpenSSL error: %.*s", len, buf);
}

void bail(int success){
  if(!success)
    raise_error();
}

