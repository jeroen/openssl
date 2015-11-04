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
#' @param password either a hardcoded string or a callback function that
#' returns a string. Only required if key is protected with a passphrase.
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
  if(!is.raw(pubkey))
    pubkey <- read_pem(pubkey)
  if(inherits(pubkey, "rsa.private"))
    pubkey <- priv2pub(pubkey)
  if(!is.raw(msg))
    stop("message must be raw vector")
  .Call(R_rsa_encrypt, msg, pubkey)
}

#' @useDynLib openssl R_rsa_decrypt
#' @export
#' @rdname rsa
rsa_decrypt <- function(ciphertext, key = "~/.ssh/id_rsa", password = readline){
  if(!is.raw(key)){
    key <- read_pem(key, password)
    if(!inherits(key, "rsa.private"))
      stop("key must be rsa private key")
  }
  if(!is.raw(ciphertext))
    stop("ciphertext must raw vector")
  .Call(R_rsa_decrypt, ciphertext, key)
}

#' @useDynLib openssl R_priv2pub
priv2pub <- function(bin){
  stopifnot(is.raw(bin))
  out <- .Call(R_priv2pub, bin)
  structure(out, class = c("rsa", "pubkey"))
}

#' @useDynLib openssl R_cert2pub
cert2pub <- function(bin){
  stopifnot(is.raw(bin))
  out <- .Call(R_cert2pub, bin)
  structure(out, class = c("rsa", "pubkey"))
}
