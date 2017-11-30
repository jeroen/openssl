#' PKCS7 / PKCS12 bundles
#'
#' PKCS7 and PKCS12 are container formats for storing multiple certificates and/or keys.
#'
#' The PKCS#7 or P7B format is a container for one or more certificates. It can either
#' be stored in binary form or in a PEM file. P7B files are typically used to import
#' and export public certificates.
#'
#' The PKCS#12 or PFX format is a binary-only format for storing the server certificate,
#' any intermediate certificates, and the private key into a single encryptable file.
#' PFX files are usually found with the extensions .pfx and .p12. PFX files are typically
#' used to import and export certificates with their private keys.
#'
#' The PKCS formats also allow for including signatures and CRLs but this is quite rare
#' and these are currently ignored.
#'
#' @export
#' @rdname pkcs12
#' @aliases pkcs12 pfx
#' @param key a private key
#' @param cert certificate that matches `key`
#' @param ca a list of certificates (the CA chain)
#' @param name a friendly title for the bundle
#' @param password string or function to set/get the password.
#' @param path a file where to write the output to. If `NULL` the output is returned
#' as a raw vector.
#' @useDynLib openssl R_write_pkcs12
write_p12 <- function(key = NULL, cert = NULL, ca = NULL, name = NULL, password = NULL, path = NULL){
  if(!length(key) && !length(cert) && !length(ca))
    stop("Either 'key' or 'cert' or 'ca' must be given")
  if(is.function(password))
    password <- password("Enter a new password for your p12 file")
  if(length(key)) key <- read_key(key)
  if(length(cert)) cert <- read_cert(cert)
  if(length(name)) stopifnot(is.character(name))
  if(length(password)) stopifnot(is.character(password))
  bin <- .Call(R_write_pkcs12, key, cert, ca, name, password)
  if(is.null(path)) return(bin)
  writeBin(bin, path)
  invisible(path)
}

#' @export
#' @rdname pkcs12
#' @useDynLib openssl R_write_pkcs7
#' @param der set to TRUE for binary files and FALSE for PEM files
write_p7b <- function(ca, path = NULL){
  ca <- if(inherits(ca, "cert")) {
    list(ca)
  } else {
    lapply(ca, read_cert)
  }
  bin <- .Call(R_write_pkcs7, ca)
  if(is.null(path)) return(bin)
  writeBin(bin, path)
  invisible(path)
}

#' @export
#' @rdname pkcs12
#' @param file path or raw vector with binary PKCS12 data to parse
read_p12 <- function(file, password = askpass){
  buf <- read_input(file)
  data <- parse_pkcs12(buf, password)
  out <- list(name = data[[4]], cert = NULL, key = NULL, ca = NULL)
  if(length(data[[1]]))
    out$cert <- read_cert(data[[1]], der = TRUE)
  if(length(data[[2]]))
    out$key <- read_key(data[[2]], der = TRUE)
  if(length(data[[3]]))
    out$ca <- lapply(data[[3]], read_cert, der = TRUE)
  return(out)
}

#' @export
#' @rdname pkcs12
read_p7b <- function(file, der = is.raw(file)){
  buf <- read_input(file)
  if(!isTRUE(der)){
    buf <- parse_pem_pkcs7(buf)
  }
  data <- structure(parse_der_pkcs7(buf), names = c("certs", "crl"))
  # Don't return the CRL, nobody seems to use that
  lapply(data$certs, read_cert)
}

#' @useDynLib openssl R_parse_pkcs12
parse_pkcs12 <- function(buf, password){
  .Call(R_parse_pkcs12, buf, password)
}

#' @useDynLib openssl R_parse_der_pkcs7
parse_der_pkcs7 <- function(buf){
  .Call(R_parse_der_pkcs7, buf)
}

#' @useDynLib openssl R_parse_pem_pkcs7
parse_pem_pkcs7 <- function(buf){
  .Call(R_parse_pem_pkcs7, buf)
}
