#' Export key or certificate
#'
#' The \code{write_pem} functions exports a key or certificate to the standard
#' base64 PEM format. For private keys it is possible to set a password.
#'
#' @export
#' @param x a public/private key or certificate object
#' @param password string or callback function to set password (only applicable for
#' private keys).
#' @param path file to write to. If \code{NULL} it returns the output as a string.
#' @rdname write_pem
write_pem <- function(x, password = readline, path = NULL){
  str <- pem_export(x, password)
  if(is.null(path)) return(str)
  writeLines(str, path)
}

#' @export
#' @rdname write_pem
write_der <- function(x, path = NULL){
  bin <- der_export(x)
  if(is.null(path)) return(bin)
  writeBin(unclass(bin), path)
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
    password <- password("Enter new passphrase: ")
  stopifnot(is.character(password) || is.null(password))
  .Call(R_pem_write_key, x, password)
}

#' @useDynLib openssl R_pem_write_pubkey
pem_export.pubkey <- function(x, ...){
  .Call(R_pem_write_pubkey, x)
}

der_export.key <- function(x, ...){
  unclass(x)
}

der_export.pubkey <- function(x, ...){
  unclass(x)
}
