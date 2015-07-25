#' Certificates
#'
#' Stuff for certificates
#'
#' @export
#' @useDynLib openssl R_certinfo
#' @param cert a certificate
#' @param root a root certificate or path to CA bundle
#' @rdname certs
certinfo <- function(cert){
  stopifnot(is.raw(cert))
  .Call(R_certinfo, cert)
}

#' @useDynLib openssl R_verify_cert
#' @export
#' @rdname certs
#' @name certs
verify_cert <- function(cert, root = system.file("cacert.pem", package = "openssl")){
  stopifnot(is.raw(cert))
  if(is.character(root)){
    root <- normalizePath(path.expand(root), mustWork = TRUE)
  } else {
    stopifnot(is.raw(root))
  }
  .Call(R_verify_cert, cert, root)
}
