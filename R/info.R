#' OpenSSL Info
#'
#' Shows libssl version and configuration information.
#'
#' @export
#' @useDynLib openssl R_openssl_info
openssl_info <- function(){
  out <- .Call(R_openssl_info)
  structure(out, names = c("version", "ec"))
}
