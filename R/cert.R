#' Certificates
#'
#' Verify a certificate
#'
#' @useDynLib openssl R_cert_verify_cert R_pubkey_verify_cert
#' @export
#' @rdname certs
#' @param cert certficate (or certificate-chain) to be verified. Must be cert or list or path.
#' @param root trusted pubkey or certificate(s) e.g. CA bundle.
cert_verify <- function(cert, root = ca_bundle()){
  if(is.raw(cert))
    cert <- list(cert)
  if(!is.list(cert))
    cert <- read_cert_bundle(cert)
  stopifnot(inherits(cert[[1]], "cert"))
  if(!is.raw(root) && !is.list(root)){
    buf <- read_input(root)
    info <- parse_pem(buf)
    if(grepl("CERT", info$name)){
      root <- read_cert_bundle(root)
    } else {
      root <- read_pubkey(root)
    }
  }
  if(inherits(root, "pubkey")){
    pubkey_verify_cert(cert[[1]], root)
  } else {
    stopifnot(all(sapply(root, inherits, "cert")))
    cert_verify_cert(cert[[1]], cert[-1], root)
  }
}

#' @useDynLib openssl R_cert_verify_cert
cert_verify_cert <- function(cert, chain, root){
  .Call(R_cert_verify_cert, cert, chain, root)
}

#' @useDynLib openssl R_pubkey_verify_cert
pubkey_verify_cert <- function(cert, pubkey){
  .Call(R_pubkey_verify_cert, cert, pubkey)
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
  structure(out, names = c("subject", "issuer", "algorithm", "signature", "validity", "self_signed"))
}
