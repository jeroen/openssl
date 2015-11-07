#' Certificates
#'
#' Stuff for certificates
#'
#' @export
#' @useDynLib openssl R_cert_info
#' @param cert a certificate
#' @param root a root certificate or path to CA bundle
#' @rdname certs
cert_info <- function(cert){
  stopifnot(is.raw(cert))
  out <- .Call(R_cert_info, cert)
  structure(out, names = c("subject", "issuer", "algorithm", "signature", "validity"))
}

#' @useDynLib openssl R_verify_cert
#' @export
#' @rdname certs
#' @name certs
verify_cert <- function(cert, root = system.file("cacert.pem", package = "openssl")){
  cert <- read_cert(cert)
  bundle <- read_cert_bundle(root)
  stopifnot(is.raw(cert))
  if(is.character(root)){
    root <- normalizePath(path.expand(root), mustWork = TRUE)
  } else {
    stopifnot(is.raw(root))
  }
  .Call(R_verify_cert, cert, root)
}
