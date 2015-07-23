#' RSA encryption and signing
#'
#' Asymmetric encryption/decryption and signature verification using RSA.
#' RSA messages have a max length of 245 bytes. Typically RSA is used to
#' exchange a symmetric key for encrypting larger data using e.g. AES.
#'
#' @export
#' @param msg raw vector of max 245 bytes with data to encrypt
#' @param ciphertext raw vector with encrypted message
#' @param key file path or raw/character vector with RSA private key
#' @param pubkey file path or raw/character vector with RSA public key
#' @rdname rsa
#' @useDynLib openssl R_rsa_encrypt
#' @export
#' @rdname rsa
#' @name rsa
#' @examples \dontrun{
#' # encrypt some data using e.g. AES
#' tempkey <- rand_bytes(32)
#' iv <- rand_bytes(16)
#' blob <- aes_cbc_encrypt(system.file("CITATION"), tempkey, iv = iv)
#'
#' #encrypt temp key using receivers public RSA key
#' cryptkey <- rsa_encrypt(tempkey, "~/.ssh/id_rsa.pub")
#'
#' #receiver decrypts tempkey from private RSA key
#' tempkey <- rsa_decrypt(cryptkey, "~/.ssh/id_rsa")
#' message <- aes_cbc_decrypt(blob, tempkey, iv)
#' cat(rawToChar(message))
#' }
rsa_encrypt <- function(msg, pubkey = "~/.ssh/id_rsa.pub"){
  key <- read_rsa(pubkey)
  if(inherits(key, "rsa.private"))
    key <- priv2pub(key)
  if(!is.raw(msg))
    stop("message must be raw vector")
  .Call(R_rsa_encrypt, msg, key)
}

#' @useDynLib openssl R_rsa_decrypt
#' @export
#' @rdname rsa
rsa_decrypt <- function(ciphertext, key = "~/.ssh/id_rsa"){
  key <- read_rsa(key)
  if(!inherits(key, "rsa.private"))
    stop("key must be rsa private key")
  if(!is.raw(ciphertext))
    stop("ciphertext must raw vector")
  .Call(R_rsa_decrypt, ciphertext, key)
}

read_rsa <- function(text, password = readlines("Enter password")){
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

#' @useDynLib openssl R_priv2pub
priv2pub <- function(bin){
  stopifnot(is.raw(bin))
  .Call(R_priv2pub, bin)
}

# Check if input is a file
path_or_data <- function(x){
  if(is.character(x)){
    if(length(x) == 1 && file.exists(x)){
      readBin(x, raw(), file.info(x)$size)
    } else {
      charToRaw(paste(x, collapse = "\n"))
    }
  } else {
    x
  }
}
