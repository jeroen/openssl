#include <Rinternals.h>
#include <openssl/err.h>
#include <string.h>
#include "utils.h"

/* Todo: try to use same error format for OpenSSL 1.1. and OpenSSL 3.0 */
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
static int copy_err_to_buf(const char *str, size_t len, void *u){
  char *dst = u;
  strncpy(dst, str, len);
  return len;
}
void raise_error(){
  char buf[8192] = {0};
  ERR_print_errors_cb(copy_err_to_buf, buf); /* Only keeps the last error from the stack */
  Rf_error("OpenSSL error: %s", buf);
}
#else
void raise_error(){
  unsigned long err = ERR_get_error(); //Pops earliest error from the queue
  ERR_clear_error(); //Removes additional errors (if any) from the queue
  stop("OpenSSL error in %s: %s", ERR_func_error_string(err), ERR_reason_error_string(err));
}
#endif

void bail(int success){
  if(!success)
    raise_error();
}

