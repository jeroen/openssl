#include <Rinternals.h>
#include <openssl/err.h>

void raise_error(){
  unsigned long err = ERR_get_error();
  Rf_errorcall(R_NilValue, "OpenSSL error in %s: %s", ERR_func_error_string(err), ERR_reason_error_string(err));
}

void bail(int success){
  if(!success)
    raise_error();
}
