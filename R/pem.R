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
#' @param file a connection, file path or character vector with literal data
#' @param read multiple PEM keys or certificates from a single file
#' @param password a string or callback function
#' @export
#' @rdname pem
read_pem <- function(file, multiple = FALSE, password = readline){
  # file can be path, connection or literal data
  stopifnot(is.character(file) || inherits(file, "connection"))
  if(is.character(file)){
    # Test for file path
    file <- if(length(file) == 1 && !grepl("^ssh-rsa ", file) && !grepl("\n", file)) {
      stopifnot(file.exists(file))
      file(file)
    } else {
      textConnection(file)
    }
  }

  # read data
  text <- paste(readLines(file, warn = FALSE), collapse = "\n")
  if(multiple){
    lapply(extract_pems(text), parse_pem, password = password)
  } else {
    parse_pem(text, password = password)
  }
}

extract_pems <- function(text){
  pattern <- "(-+BEGIN)(.+?)(-+END)(.+?)(-+)"
  m <- gregexpr(pattern, text)
  regmatches(text, m)[[1]]
}

parse_pem <- function(text, password){
  # parse based on header
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

#' @export
#' @rdname pem
write_pem <- function(key){
  stopifnot(is.raw(key))
  type <- if(inherits(key, "rsa.private")){
    "RSA PRIVATE KEY"
  } else if(inherits(key, "rsa.pubkey")){
    "PUBLIC KEY"
  } else if(inherits(key, "x509.cert")){
    "CERTIFICATE"
  } else {
    stop("Unknown type.")
  }
  paste0(
    "-----BEGIN ", type ,"-----\n",
    base64_encode(key, linebreaks = TRUE),
    "-----END ", type, "-----\n"
  )
}
