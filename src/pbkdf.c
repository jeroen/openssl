#include <Rinternals.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u_int8_t;

int bcrypt_pbkdf(const char *pass, size_t passlen, const u_int8_t *salt,
                 size_t saltlen, u_int8_t *key, size_t keylen, unsigned int rounds);

SEXP R_bcrypt_pbkdf(SEXP pass, SEXP salt, SEXP rounds, SEXP size){
  int len = Rf_asInteger(size);
  SEXP key = PROTECT(Rf_allocVector(RAWSXP, len));
  if(bcrypt_pbkdf((char*) RAW(pass), Rf_length(pass), RAW(salt), Rf_length(salt),
               RAW(key), Rf_length(key), Rf_asInteger(rounds)) != 0){
    Rf_error("Failure in bcrypt key-derivation");
  }
  UNPROTECT(1);
  return key;
}
