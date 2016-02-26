#' OpenSSL Configuration Info
#'
#' Shows libssl version and configuration information.
#'
#' @export
#' @useDynLib openssl R_openssl_config
openssl_config <- function(){
  out <- .Call(R_openssl_config)
  structure(out, names = c("version", "ec"))
}
