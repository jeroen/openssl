#include <Rinternals.h>
#include <openssl/err.h>
#include "utils.h"

void raise_error(){
  unsigned long err = ERR_get_error(); //Pops earliest error from the queue
  ERR_clear_error(); //Removes additional errors (if any) from the queue
  stop("OpenSSL error in %s: %s", ERR_func_error_string(err), ERR_reason_error_string(err));
}

void bail(int success){
  if(!success)
    raise_error();
}

