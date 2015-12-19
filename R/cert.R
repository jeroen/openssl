#' X509 certificates
#'
#' Read, download, analyize and verify X.509 certificates.
#'
#' @useDynLib openssl R_cert_verify_cert R_pubkey_verify_cert
#' @export
#' @rdname certificates
#' @seealso \link{read_cert}
#' @param cert certficate (or certificate-chain) to be verified. Must be cert or list or path.
#' @param root trusted pubkey or certificate(s) e.g. CA bundle.
#' @examples # Verify the r-project HTTPS cert
#' chain <- download_ssl_cert("www.r-project.org", 443)
#' print(chain)
#' print(as.list(chain[[1]])$pubkey)
#' cert_verify(chain, ca_bundle())
#'
#' # Another example
#' chain <- download_ssl_cert("public.opencpu.org")
#' ocpu <- chain[[1]]
#' as.list(ocpu)$subject
#'
#' # Write PEM format
#' write_pem(ocpu)
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

#' @useDynLib openssl R_download_cert
#' @export
#' @rdname certificates
#' @param host string: hostname of the server to connect to
#' @param port string or integer: port or protocol to use, e.g: \code{443} or \code{"https"}
download_ssl_cert <- function(host = "localhost", port = 443){
  if(grepl("https?://", host))
    stop("Argument 'host' must be a hostname, not url. Take out the https:// prefix.")
  stopifnot(is.character(host))
  .Call(R_download_cert, host, as.character(port))
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
