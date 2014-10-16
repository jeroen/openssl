#include <openssl/rand.h>
#include <R.h>
#include <Rinternals.h>

SEXP R_RAND_pseudo_bytes(SEXP n, SEXP pseudo) {
  int use_pseudo = asLogical(pseudo);
  int length = asInteger(n);
  int result;
  unsigned char buf[length];
  if(use_pseudo){
    result = RAND_pseudo_bytes(buf, length);
  } else {
    result = RAND_bytes(buf, length);
  }
  if(!result) {
    error("Failed to generated pseudo random bytes.");
  }

  SEXP out = PROTECT(allocVector(RAWSXP, length));
  for (int i = 0; i < length; i++) {
    RAW(out)[i] = buf[i];
  }
  UNPROTECT(1);
  return out;
}
