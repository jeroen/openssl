#' @useDynLib openssl R_download_cert
#' @export
download_cert <- function(host = "localhost", port = 443){
  stopifnot(is.character(host))
  stopifnot(is.numeric(port))
  .Call(R_download_cert, host, as.integer(port))
}
