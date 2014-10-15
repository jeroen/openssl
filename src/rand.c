#include <openssl/rand.h>
#include <R.h>
#include <Rinternals.h>

SEXP R_RAND_pseudo_bytes(SEXP length, SEXP pseudo) {
  int use_pseudo = asLogical(pseudo);
  int num = asInteger(length);
  int result;
  unsigned char buf[num];
  if(use_pseudo){
    result = RAND_pseudo_bytes(buf, num);
  } else {
    result = RAND_bytes(buf, num);
  }
  if(!result) {
    error("Failed to generated pseudo random bytes.");
  }

  SEXP out = PROTECT(allocVector(RAWSXP, num));
  for (int i = 0; i < num; i++) {
    RAW(out)[i] = buf[i];
  }
  UNPROTECT(1);
  return out;
}
