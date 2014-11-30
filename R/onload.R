.onLoad <- function(libname, pkgname){
  .Call(R_openssl_init)
}

.onUnLoad <- function(libpath){
  .Call(R_openssl_cleanup)
}
