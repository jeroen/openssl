#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>

int password_cb(char *buf, int max_size, int rwflag, void *ctx){
  if(!ctx)
    Rf_error("No password callback supplied.");

  SEXP cb = (SEXP) ctx;

  /* no password */
  if(Rf_isNull(cb)){
    return 0;
  }

  /* case where password is a hardcoded string */
  if(Rf_isString(cb)){
    strncpy(buf, CHAR(STRING_ELT(cb, 0)), max_size);
    buf[max_size-1] = '\0'; //in case of max size
    return strlen(buf);
  }

  /* case where password is an R function */
  if(Rf_isFunction(cb)){
    int err;
    SEXP prompt = PROTECT(Rf_mkString("Please enter private key passphrase: "));
    Rf_setAttrib(prompt, R_NamesSymbol, Rf_mkString("PRIVATE KEY"));
    SEXP call = PROTECT(Rf_lcons(cb, Rf_lcons(prompt, R_NilValue)));
    SEXP res = PROTECT(R_tryEval(call, R_GlobalEnv, &err));
    if(err || !Rf_isString(res)){
      Rf_error("Password callback did not return a string value");
    }
    strncpy(buf, CHAR(STRING_ELT(res, 0)), max_size);
    buf[max_size-1] = '\0';
    UNPROTECT(3);
    return strlen(buf);
  }
  Rf_error("Callback must be string or function");
}
