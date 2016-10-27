#' PKCS12 bundles
#'
#' PKCS12 is a format for bundling a private key, a certificate and a certificate chain
#' in a single password-protected file. At least one of `key`, `cert` or `ca` must
#' be non-NULL.
#'
#' @export
#' @rdname pkcs12
#' @aliases pkcs12
#' @param key a private key
#' @param cert certificate that matches `key`
#' @param ca a list of certificates stores in as the ca chain
#' @param name a friendly title for the bundle
#' @param password string or function to set/get the password.
#' @param path a file where to write the output to. If `NULL` the output is returned
#' as a raw vector.
#' @useDynLib openssl R_write_pkcs12
write_pkcs12 <- function(key = NULL, cert = NULL, ca = NULL, name = NULL, password = NULL, path = NULL){
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
#' @param file path or raw vector with binary PKCS12 data to parse
read_pkcs12 <- function(file, password = askpass){
  buf <- read_input(file)
  data <- parse_pkcs12(buf, password)
  out <- list(cert = NULL, key = NULL, ca = NULL)
  if(length(data[[1]]))
    out$cert <- read_cert(data[[1]], der = TRUE)
  if(length(data[[2]]))
    out$key <- read_key(data[[2]], der = TRUE)
  if(length(data[[3]]))
    out$ca <- lapply(data[[3]], read_cert, der = TRUE)
  return(out)
}

#' @useDynLib openssl R_parse_pkcs12
parse_pkcs12 <- function(buf, password){
  .Call(R_parse_pkcs12, buf, password)
}
