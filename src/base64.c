#include <Rinternals.h>
#include <limits.h>
#include <openssl/evp.h>
#include "compatibility.h"

/* Output buffers are allocated by R and the EVP_ENCODE_CTX is freed
 * before raising any error, so nothing can leak. */

SEXP R_base64_encode(SEXP bin, SEXP linebreaks){
  int len = LENGTH(bin);
  if(len > INT_MAX / 3)
    Rf_error("Input is too large to base64 encode");
  int b64len = 4 * ((len + 2) / 3);

  //EVP_EncodeBlock does not insert linebreaks
  if(!Rf_asLogical(linebreaks)){
    SEXP buf = PROTECT(Rf_allocVector(RAWSXP, b64len + 1));
    EVP_EncodeBlock(RAW(buf), RAW(bin), len);
    SEXP out = PROTECT(Rf_ScalarString(Rf_mkCharLen((const char*) RAW(buf), b64len)));
    UNPROTECT(2);
    return out;
  }

  //EVP_EncodeUpdate writes lines of 64 chars, each terminated by a newline
  SEXP buf = PROTECT(Rf_allocVector(RAWSXP, b64len + (b64len + 63) / 64 + 1));
  int outlen = 0, finlen = 0;
  EVP_ENCODE_CTX *ctx = MY_EVP_ENCODE_CTX_new();
  if(ctx == NULL)
    Rf_error("Failed to allocate EVP_ENCODE_CTX");
  EVP_EncodeInit(ctx);
  EVP_EncodeUpdate(ctx, RAW(buf), &outlen, RAW(bin), len);
  EVP_EncodeFinal(ctx, RAW(buf) + outlen, &finlen);
  MY_EVP_ENCODE_CTX_free(ctx);
  SEXP out = PROTECT(Rf_ScalarString(Rf_mkCharLen((const char*) RAW(buf), outlen + finlen)));
  UNPROTECT(2);
  return out;
}

SEXP R_base64_decode(SEXP text){
  const unsigned char *str = (const unsigned char*) CHAR(STRING_ELT(text, 0));
  int len = LENGTH(STRING_ELT(text, 0));

  //EVP_DecodeUpdate skips whitespace and validates the padding
  SEXP bin = PROTECT(Rf_allocVector(RAWSXP, (len / 4 + 1) * 3));
  int outlen = 0, finlen = 0;
  EVP_ENCODE_CTX *ctx = MY_EVP_ENCODE_CTX_new();
  if(ctx == NULL)
    Rf_error("Failed to allocate EVP_ENCODE_CTX");
  EVP_DecodeInit(ctx);
  int ok = EVP_DecodeUpdate(ctx, RAW(bin), &outlen, str, len) >= 0 &&
    EVP_DecodeFinal(ctx, RAW(bin) + outlen, &finlen) > 0;
  MY_EVP_ENCODE_CTX_free(ctx);
  if(!ok)
    Rf_error("Failed to decode base64 string");
  SEXP out = PROTECT(Rf_lengthgets(bin, outlen + finlen));
  UNPROTECT(2);
  return out;
}
