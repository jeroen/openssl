#' Read keys and certificates
#'
#' Read from a file or buffer in DER or PEM format.
#'
#'
#'
#' @export
#' @rdname read_key
read_key <- function(file, password = readline, format = c("pem", "der")){
  buf <- read_input(file)
  format <- match.arg(format)
  key <- switch(format,
    "pem" = parse_pem_key(buf, password),
    "der" = parse_der_key(buf))
  structure(key, class = "key")
}

#' @export
#' @rdname read_key
read_pubkey <- function(file, password = readline, format = c("pem", "der", "ssh")){
  buf <- read_input(file)
  format <- match.arg(format)
  key <- switch(format,
    "pem" = parse_pem_pubkey(buf, password),
    "der" = parse_der_pubkey(buf),
    "ssh" = parse_ssh_pubkey(buf))
  structure(key, class = "pubkey")
}

#' @export
#' @rdname read_key
read_cert <- function(file, format = c("pem", "der")){
  buf <- read_input(file)
  format <- match.arg(format)
  key <- switch(format,
    "pem" = parse_pem_cert(buf, password),
    "der" = parse_der_cert(buf))
  structure(key, class = "cert")
}

read_input <- function(x){
  if(is.raw(x)){
    x
  } else if(inherits(x, "connection")){
    readBin(x, raw(), file.info(x)$size)
  } else if(is.character(x) && length(x) == 1 && !grepl("\n", x)){
    stopifnot(file.exists(x))
    readBin(x, raw(), file.info(x)$size)
  } else if(is.character(x)) {
    charToRaw(paste(x, collapse = "\n"))
  } else {
    stop("file must be connection, raw vector or file path")
  }
}

#' @useDynLib openssl R_parse_pem_name
read_pem <- function(file){
  buf <- read_input(file)
  .Call(R_parse_pem_name, buf)
}


split_pem <- function(text) {
  pattern <- "(-+BEGIN)(.+?)(-+END)(.+?)(-+)"
  m <- gregexpr(pattern, text)
  regmatches(text, m)[[1]]
}

guess_pem_type <- function(text){
  if(grepl("-BEGIN (RSA |ENCRYPTED )?PRIVATE KEY-", text)){
    "private"
  } else if(grepl("-BEGIN RSA PUBLIC KEY-", text, fixed = TRUE)){
    "pkcs1"
  } else if(grepl("-BEGIN PUBLIC KEY-", text, fixed = TRUE)){
    "pkcs8"
  } else if(grepl("-- BEGIN SSH2 PUBLIC KEY --", text, fixed = TRUE)){
    "ssh2"
  } else if(grepl("-BEGIN CERTIFICATE-", text, fixed = TRUE)){
    "cert"
  } else if(grepl("^ssh-rsa ", text[1])) {
    "openssh"
  } else {
    NULL
  }
}

#' @useDynLib openssl R_parse_pem_key
parse_pem_key <- function(buf, password){
  .Call(R_parse_pem_key, buf)
}

#' @useDynLib openssl R_parse_der_key
parse_der_key <- function(buf){
  .Call(R_parse_der_key, buf)
}

#' @useDynLib openssl R_parse_pem_pubkey R_parse_pem_pkcs1
parse_pem_pubkey <- function(buf, password){
  type <- guess_pem_type(rawToChar(buf))
  switch(type,
    "pkcs1" = .Call(R_parse_pem_pkcs1, buf),
    "ssh2" = parse_ssh_pem(buf),
    .Call(R_parse_pem_pubkey, buf)
  )
}

#' @useDynLib openssl R_parse_der_pubkey
parse_der_pubkey <- function(buf){
  .Call(R_parse_der_pubkey, buf)
}

parse_ssh_pubkey <- function(buf){

}

parse_ssh_pem <- function(buf){

}

#' @useDynLib openssl R_parse_pem_cert
parse_pem_cert <- function(buf, password){
  .Call(R_parse_pem_cert, buf)
}

#' @useDynLib openssl R_parse_der_cert
parse_der_cert <- function(buf){
  .Call(R_parse_der_cert, buf)
}
