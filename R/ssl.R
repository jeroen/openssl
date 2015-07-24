#' Download Certificate
#'
#' Connects to a HTTPS server and retrieves the SSL certificate.
#'
#' @useDynLib openssl R_download_cert
#' @export
#' @param host string: hostname of the server to connect to
#' @param port integer: port to connect to
download_cert <- function(host = "localhost", port = 443){
  stopifnot(is.character(host))
  stopifnot(is.numeric(port))
  .Call(R_download_cert, host, as.integer(port))
}
