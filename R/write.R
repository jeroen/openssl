#' Export key or certificate
#'
#' The \code{write_pem} functions exports a key or certificate to the standard
#' base64 PEM format. For private keys it is possible to set a password.
#'
#' The pkcs1 format is a legacy format which only supports RSA keys and should
#' not be used anymore. It is only provided for compatibility with some old SSH
#' clients. Simply use \code{write_pem} to export keys and certs to the recommended
#' format.
#'
#' @export
#' @param x a public/private key or certificate object
#' @param password string or callback function to set password (only applicable for
#' private keys).
#' @param path file to write to. If \code{NULL} it returns the output as a string.
#' @rdname write_pem
write_pem <- function(x, path = NULL, password = NULL){
  str <- pem_export(x, password)
  if(is.null(path)) return(str)
  writeLines(str, path)
  invisible(path)
}

#' @export
#' @rdname write_pem
write_der <- function(x, path = NULL){
  bin <- der_export(x)
  if(is.null(path)) return(bin)
  writeBin(unclass(bin), path)
  invisible(path)
}

#' @export
#' @rdname write_pem
#' @useDynLib openssl R_pem_write_pkcs1_privkey R_pem_write_pkcs1_pubkey
write_pkcs1 <- function(x, path = NULL, password = NULL){
  if(!inherits(x, "rsa"))
    stop("PKCS1 only supports RSA keys")
  str <- if(inherits(x, "key"))
    .Call(R_pem_write_pkcs1_privkey, x, password)
  else
    .Call(R_pem_write_pkcs1_pubkey, x)
  if(is.null(path)) return(str)
  writeLines(str, path)
  invisible(path)
}

pem_export <- function(x, ...){
  UseMethod("pem_export")
}

der_export <- function(x, ...){
  UseMethod("der_export")
}

#' @useDynLib openssl R_pem_write_key
pem_export.key <- function(x, password, ...){
  if(is.function(password))
    password <- password("Enter new passphrase (or hit ENTER for no password): ")
  stopifnot(is.character(password) || is.null(password))
  .Call(R_pem_write_key, x, password)
}

#' @useDynLib openssl R_pem_write_pubkey
pem_export.pubkey <- function(x, ...){
  .Call(R_pem_write_pubkey, x)
}


#' @useDynLib openssl R_pem_write_cert
pem_export.cert <- function(x, ...){
  .Call(R_pem_write_cert, x)
}

der_export.key <- function(x, ...){
  unclass(x)
}

der_export.pubkey <- function(x, ...){
  unclass(x)
}

der_export.cert <- function(x, ...){
  unclass(x)
}
