#' Reading an SSL_CTX pointer
#'
#' Reads data from a pointer to an SSL_CTX object that is provided
#' via another library such as curl.
#'
#' @useDynLib openssl R_ssl_ctx_info
#' @export
#' @param ptr an external pointer object of class ssl_ctx
ssl_ctx_info <- function(ptr){
  stopifnot(inherits(ptr, 'ssl_ctx'))
  .Call(R_ssl_ctx_info, ptr)
}
