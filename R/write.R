#' @export
#' @rdname read_key
write_pem <- function(x, password = readline, path = NULL){
  str <- pem_export(x, password)
  if(is.null(path)) return(str)
  writeLines(str, path)
}

pem_export <- function(x, ...){
  UseMethod("pem_export")
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

#' @export
#' @rdname read_key
write_der <- function(x, path = NULL){
  bin <- der_export(x)
  if(is.null(path)) return(bin)
  writeBin(unclass(bin), path)
}

der_export <- function(x, ...){
  UseMethod("der_export")
}

der_export.key <- function(x, ...){
  unclass(x)
}

der_export.pubkey <- function(x, ...){
  unclass(x)
}
