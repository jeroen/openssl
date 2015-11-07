#' Certificates
#'
#' Verify a certificate
#'
#' @useDynLib openssl R_cert_verify
#' @export
#' @rdname certs
#' @param chain certficate (or certificate-chain) to be verified. Must be cert or list or path.
#' @param root trusted root certificates (e.g. CA bundle). Must be cert or list or path.
cert_verify <- function(chain, root = ca_bundle()){
  if(is.raw(root))
    root <- list(root)
  if(!is.list(root))
    root <- read_cert_bundle(root)
  if(is.raw(chain))
    chain <- list(chain)
  if(!is.list(chain))
    chain <- read_cert_bundle(chain)
  .Call(R_cert_verify, chain[[1]], chain[-1], root)
}

#' @export
#' @rdname certs
ca_bundle <- function(){
  path <- system.file("cacert.pem", package = "openssl")
  read_cert_bundle(path)
}

#' @useDynLib openssl R_cert_info
cert_info <- function(cert){
  stopifnot(is.raw(cert))
  out <- .Call(R_cert_info, cert)
  structure(out, names = c("subject", "issuer", "algorithm", "signature", "validity"))
}
