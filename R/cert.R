#' Certificates
#'
#' Stuff for certificates
#'
#' @export
#' @useDynLib openssl R_certinfo
#' @param cert a certificate
#' @param ca a CA bundle
#' @rdname certs
certinfo <- function(cert){
  stopifnot(is.raw(cert))
  .Call(R_certinfo, cert)
}

#' @useDynLib openssl R_verify_cert
#' @export
#' @rdname certs
#' @name certs
verify_cert <- function(cert, ca){
  stopifnot(is.raw(cert))
  stopifnot(is.raw(ca))
  .Call(R_verify_cert, cert, ca)
}
