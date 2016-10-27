#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "utils.h"

SEXP R_RAND_bytes(SEXP n) {
  int length = asInteger(n);
  if(length <= 0)
    return allocVector(RAWSXP, 0);
  unsigned char buf[length];
  bail(RAND_bytes(buf, length));
  SEXP out = PROTECT(allocVector(RAWSXP, length));
  memcpy(RAW(out), buf, length);
  UNPROTECT(1);
  return out;
}
