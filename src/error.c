#include <Rinternals.h>
#include "apple.h"
#include <openssl/err.h>
#include "utils.h"

void raise_error(){
  unsigned long err = ERR_get_error();
  stop("OpenSSL error in %s: %s", ERR_func_error_string(err), ERR_reason_error_string(err));
}

void bail(int success){
  if(!success)
    raise_error();
}

