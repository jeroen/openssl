#' X509 certificates
#'
#' Read, download, analyze and verify X.509 certificates.
#'
#' @useDynLib openssl R_cert_verify_cert R_pubkey_verify_cert
#' @export
#' @rdname certificates
#' @aliases certificates
#' @seealso [read_cert]
#' @param cert certificate (or certificate-chain) to be verified. Must be cert or list or path.
#' @param root trusted pubkey or certificate(s) e.g. CA bundle.
#' @examples \donttest{
#' # Verify the r-project HTTPS cert
#' chain <- download_ssl_cert("cran.r-project.org", 443)
#' print(chain)
#' cert_data <- as.list(chain[[1]])
#' print(cert_data$pubkey)
#' print(cert_data$alt_names)
#' cert_verify(chain, ca_bundle())
#'
#' # Write cert in PEM format
#' cat(write_pem(chain[[1]]))
#' }
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
#' @param port string or integer: port or protocol to use, e.g: `443` or `"https"`
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
#' @details The `ca_bundle()` function first looks for the default CA bundle
#' of the system libssl, which may be overridden with the `SSL_CERT_FILE`
#' environment variable. If no system bundle is found, it falls back on the
#' Mozilla CA bundle that was downloaded from <https://curl.se/ca/cacert.pem>
#' when the package was installed.
ca_bundle <- function(){
  for(path in ca_bundle_paths()){
    if(nzchar(path) && isTRUE(file.size(path) > 0)){
      bundle <- tryCatch(read_cert_bundle(path), error = function(e) NULL)
      if(length(bundle))
        return(bundle)
    }
  }
  stop("No CA bundle found on this system. Set SSL_CERT_FILE to the path of a CA bundle.")
}

ca_bundle_paths <- function(){
  files <- default_cert_file()
  c(Sys.getenv(files[1]), files[2], system.file("cacert.pem", package = "openssl"))
}

#' @useDynLib openssl R_default_cert_file
default_cert_file <- function(){
  .Call(R_default_cert_file)
}

#' @useDynLib openssl R_cert_info
cert_info <- function(cert, name_format = NULL){
  stopifnot(is.raw(cert))
  if(length(name_format))
    stopifnot(is.integer(name_format))
  out <- .Call(R_cert_info, cert, name_format)
  structure(out, names = c("subject", "issuer", "algorithm", "signature", "validity", "self_signed", "alt_names"))
}
