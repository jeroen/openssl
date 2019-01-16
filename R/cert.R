#' X509 certificates
#'
#' Read, download, analyze and verify X.509 certificates.
#'
#' If https verification fails and you can't figure out why, have a look
#' at \url{https://ssldecoder.org}.
#'
#' @useDynLib openssl R_cert_verify_cert R_pubkey_verify_cert
#' @export
#' @rdname certificates
#' @seealso \link{read_cert}
#' @param cert certificate (or certificate-chain) to be verified. Must be cert or list or path.
#' @param root trusted pubkey or certificate(s) e.g. CA bundle.
#' @examples # Verify the r-project HTTPS cert
#' chain <- download_ssl_cert("cloud.r-project.org", 443)
#' print(chain)
#' cert_data <- as.list(chain[[1]])
#' print(cert_data$pubkey)
#' print(cert_data$alt_names)
#' cert_verify(chain, ca_bundle())
#'
#' # Write cert in PEM format
#' cat(write_pem(chain[[1]]))
cert_verify <- function(cert, root = ca_bundle()){
  if(is.raw(cert))
    cert <- list(cert)
  if(!is.list(cert))
    cert <- read_cert_bundle(cert)
  stopifnot(inherits(cert[[1]], "cert"))
  if(inherits(root, "cert"))
    root <- list(root)
  if(!is.raw(root) && !is.list(root)){
    buf <- read_input(root)
    names <- pem_names(buf)
    if(any(grepl("CERT", names))){
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

#' @useDynLib openssl R_download_cert
#' @export
#' @rdname certificates
#' @param host string: hostname of the server to connect to
#' @param port string or integer: port or protocol to use, e.g: \code{443} or \code{"https"}
#' @param ipv4_only do not use IPv6 connections
download_ssl_cert <- function(host = "localhost", port = 443, ipv4_only = FALSE){
  if(grepl("https?://", host))
    stop("Argument 'host' must be a hostname, not url. Take out the https:// prefix.")
  stopifnot(is.character(host))
  .Call(R_download_cert, host, as.character(port), ipv4_only)
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
#' @rdname certificates
ca_bundle <- function(){
  path <- system.file("cacert.pem", package = "openssl")
  read_cert_bundle(path)
}

#' @useDynLib openssl R_cert_info
cert_info <- function(cert){
  stopifnot(is.raw(cert))
  out <- .Call(R_cert_info, cert)
  structure(out, names = c("subject", "issuer", "algorithm", "signature", "validity", "self_signed", "alt_names"))
}
