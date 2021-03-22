#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "utils.h"

SEXP R_RAND_bytes(SEXP n) {
  int length = asInteger(n);
  SEXP out = PROTECT(allocVector(RAWSXP, length));
  if(length > 0)
    bail(RAND_bytes(RAW(out), length));
  UNPROTECT(1);
  return out;
}
