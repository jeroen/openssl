#include <Rinternals.h>
#include <stdlib.h>
#include <string.h>

int password_cb(char *buf, int max_size, int rwflag, void *ctx){
  if(!ctx)
    error("No password callback supplied.");

  SEXP cb = (SEXP) ctx;

  /* no password */
  if(isNull(cb)){
    return 0;
  }

  /* case where password is a hardcoded string */
  if(isString(cb)){
    strncpy(buf, CHAR(STRING_ELT(cb, 0)), max_size);
    buf[max_size-1] = '\0'; //in case of max size
    return strlen(buf);
  }

  /* case where password is an R function */
  if(isFunction(cb)){
    int err;
    SEXP prompt = PROTECT(mkString("Please enter private key passphrase: "));
    Rf_setAttrib(prompt, R_NamesSymbol, mkString("PRIVATE KEY"));
    SEXP call = PROTECT(LCONS(cb, LCONS(prompt, R_NilValue)));
    SEXP res = PROTECT(R_tryEval(call, R_GlobalEnv, &err));
    if(err || !isString(res)){
      error("Password callback did not return a string value");
    }
    strncpy(buf, CHAR(STRING_ELT(res, 0)), max_size);
    buf[max_size-1] = '\0';
    UNPROTECT(3);
    return strlen(buf);
  }
  error("Callback must be string or function");
}
