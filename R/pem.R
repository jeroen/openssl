#' Read PEM/DER files
#'
#' DER is a binary format used for storing certificate and key data in SSL.
#' The PEM format is base64 encoded DER data surrounded by header lines and
#' possibly password protected. It is the most commonly used format to exchange
#' RSA keys and X509 certificates. It is easily recognized from the
#' \code{-- BEGIN --} and \code{-- END --} lines.
#'
#' A PEM file can contain multiple values, for example to store a certificate
#' chain. These functions parse and validates the PEM or DER input and return
#' a raw vector which holds the DER data.
#'
#' @param file a connection, file path or vector with literal data
#' @param multiple read multiple PEM keys or certificates from a single file
#' @param password a string or callback function
#' @param bin binary DER representation of a key or cert
#' @export
#' @rdname pem
#' @export
#' @rdname pem
read_der <- function(file, type = c("guess", "cert", "key", "pubkey")){
  bindata <- if(is.raw(file)){
    file
  } else if(inherits(file, "connection")){
    readBin(file, raw(), file.info(file)$size)
  } else if(is.character(file) && length(file) == 1 && !grepl("\n", file)){
    stopifnot(file.exists(file))
    readBin(file, raw(), file.info(file)$size)
  } else {
    stop("file must be connection, raw vector or file path")
  }
  type <- match.arg(type)
  if(type == "guess"){
    type <- guess_type(bindata)
  }
  class(bindata) <- c("rsa", type)
  read_pem(write_pem(bindata))
}

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

#' @useDynLib openssl R_parse_pkcs8
parse_pkcs8 <- function(text){
  bin <- .Call(R_parse_pkcs8, charToRaw(text))
  structure(bin, class = c("rsa", "pubkey"))
}

#' @useDynLib openssl R_parse_rsa_private
parse_rsa_private <- function(text, password = NULL){
  if(!is.character(password) && !is.function(password)){
    stop("Password must be a string or callback function")
  }
  bin <- .Call(R_parse_rsa_private, charToRaw(text), password)
  structure(bin, class = c("rsa", "key"))
}

#' @useDynLib openssl R_guess_type
guess_type <- function(bin){
  stopifnot(is.raw(bin))
  .Call(R_guess_type, bin)
}

#' @export
#' @rdname pem
write_pem <- function(bin){
  stopifnot(is.raw(bin))
  type <- if(inherits(bin, "rsa") && inherits(bin, "key")){
    "RSA PRIVATE KEY"
  } else if(inherits(bin, "rsa") && inherits(bin, "pubkey")){
    "PUBLIC KEY"
  } else if(inherits(bin, "cert")){
    "CERTIFICATE"
  } else {
    stop("Unknown type.")
  }
  paste0(
    "-----BEGIN ", type ,"-----\n",
    base64_encode(bin, linebreaks = TRUE),
    "-----END ", type, "-----\n"
  )
}
