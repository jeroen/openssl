#' Parse RSA keys
#'
#' Parse a text string containing a public or private RSA key in the
#' typical base64 encoded format.
#'
#' @export
#' @param text a path or text string containing
parse_key <- function(text, password = readlines("Enter password")){
  password <- substitute(password)
  stopifnot(is.character(text) || inherits(text, "connection"))
  if(inherits(text, "connection") || (length(text) == 1 && file.exists(text))){
    text <- readLines(text, warn = FALSE)
  }
  text <- paste(text, collapse = "\n")
  if(grepl("-BEGIN (RSA )?PRIVATE KEY-", text)){
    parse_rsa_private(text)
  } else if(grepl("-BEGIN RSA PUBLIC KEY-", text, fixed = TRUE)){
    parse_pkcs1(text)
  } else if(grepl("-BEGIN PUBLIC KEY-", text, fixed = TRUE)){
    parse_pkcs8(text)
  } else if(grepl("-- BEGIN SSH2 PUBLIC KEY --", text, fixed = TRUE)){
    parse_ssh2(text)
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

#' @useDynLib openssl R_parse_rsa_private
parse_rsa_private <- function(text){
  .Call(R_parse_rsa_private, charToRaw(text))
}

#' @useDynLib openssl R_parse_rsa_private
parse_ssh2 <- function(text){
  stop("ssh2 format not yet implemented.")
}

#' @useDynLib openssl R_priv2pub
#' @export
priv2pub <- function(bin){
  stopifnot(is.raw(bin))
  .Call(R_priv2pub, bin)
}
