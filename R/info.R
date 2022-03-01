#' OpenSSL Configuration Info
#'
#' Shows libssl version and configuration information.
#'
#' Note that the "fips" flag in `openssl_config` means that FIPS is
#' supported, but it does not mean that it is currently enforced. If
#' supported, it can be enabled in several ways, such as a kernel
#' option, or setting an environment variable `OPENSSL_FORCE_FIPS_MODE=1`.
#' The `fips_mode()` function shows if FIPS is currently enforced.
#'
#' @export
#' @useDynLib openssl R_openssl_config
openssl_config <- function(){
  out <- .Call(R_openssl_config)
  structure(out, names = c("version", "ec", "x25519", "fips"))
}


#' @rdname openssl_config
#' @export
#' @useDynLib openssl R_openssl_fips_mode
fips_mode <- function(){
  .Call(R_openssl_fips_mode)
}
