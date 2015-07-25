#' Read PEM files
#'
#' The PEM format is simply base64 encoded data surrounded by header lines.
#' It is the most commonly used format to store RSA keys and X509 certificates.
#' It is easily recognized from the \code{-- BEGIN --} and \code{-- END --}
#' lines.
#'
#' This function parses and validates the PEM file and returns the binary DER
#' representation.
#'
#' @param text a character vector or connection to a text file
#' @param password a string or callback function
#' @export
read_pem <- function(text, password = readline){
  stopifnot(is.character(text) || inherits(text, "connection"))
  if(inherits(text, "connection") || (length(text) == 1 && file.exists(text))){
    text <- readLines(text, warn = FALSE)
  }
  text <- paste(text, collapse = "\n")
  if(grepl("-BEGIN (RSA |ENCRYPTED )?PRIVATE KEY-", text)){
    parse_rsa_private(text, password)
  } else if(grepl("-BEGIN RSA PUBLIC KEY-", text, fixed = TRUE)){
    parse_pkcs1(text)
  } else if(grepl("-BEGIN PUBLIC KEY-", text, fixed = TRUE)){
    parse_pkcs8(text)
  } else if(grepl("-- BEGIN SSH2 PUBLIC KEY --", text, fixed = TRUE)){
    parse_ssh2(text)
  } else if(grepl("^ssh-rsa ", text[1])) {
    parse_openssh(text)
  } else if(grepl("-BEGIN CERTIFICATE-", text, fixed = TRUE)){
    parse_x509(text)
  } else {
    stop("Unsupported key format")
  }
}

#' @useDynLib openssl R_parse_pkcs1
parse_pkcs1 <- function(text){
  .Call(R_parse_pkcs1, charToRaw(text))
}

#' @useDynLib openssl R_parse_pkcs8
parse_pkcs8 <- function(text){
  .Call(R_parse_pkcs8, charToRaw(text))
}

#' @useDynLib openssl R_parse_x509
parse_x509 <- function(text){
  .Call(R_parse_x509, charToRaw(text))
}

#' @useDynLib openssl R_parse_rsa_private
parse_rsa_private <- function(text, password = NULL){
  if(!is.character(password) && !is.function(password)){
    stop("Password must be a string or callback function")
  }
  .Call(R_parse_rsa_private, charToRaw(text), password)
}

#' @useDynLib openssl R_priv2pub
priv2pub <- function(bin){
  stopifnot(is.raw(bin))
  .Call(R_priv2pub, bin)
}

#' @useDynLib openssl R_cert2pub
cert2pub <- function(bin){
  stopifnot(is.raw(bin))
  .Call(R_cert2pub, bin)
}
