#' Low level RSA encryption
#'
#' Asymmetric encryption and decryption with RSA. Because RSA only supports messages of
#' max 245 bytes it is typically used for exchanging a random temporary key for encrypting
#' larger data. This is implemented in the high-level enveloppe functions.
#'
#' @export
#' @param data raw vector of max 245 bytes with data to encrypt/decrypt
#' @param key private key or file path. See \code{\link{read_key}}
#' @param pubkey public key or file path. See \code{\link{read_pubkey}}
#' @param password string or a function to read protected keys. See \code{\link{read_key}}.
#' @rdname encrypt
#' @name encrypt
#' @useDynLib openssl R_rsa_encrypt
#' @examples # Generate test keys
#' key <- rsa_keygen()
#' pubkey <- as.list(key)$pubkey
#'
#' # Encrypt data with AES
#' tempkey <- rand_bytes(32)
#' iv <- rand_bytes(16)
#' blob <- aes_cbc_encrypt(system.file("CITATION"), tempkey, iv = iv)
#'
#' # Encrypt tempkey using receivers public RSA key
#' ciphertext <- rsa_encrypt(tempkey, pubkey)
#'
#' # Receiver decrypts tempkey from private RSA key
#' tempkey <- rsa_decrypt(ciphertext, key)
#' message <- aes_cbc_decrypt(blob, tempkey, iv)
#' cat(rawToChar(message))
rsa_encrypt <- function(data, pubkey = my_pubkey()){
  stopifnot(inherits(pubkey, "rsa"))
  pk <- read_pubkey(pubkey)
  stopifnot(is.raw(data))
  .Call(R_rsa_encrypt, data, pk)
}

#' @useDynLib openssl R_rsa_decrypt
#' @export
#' @rdname encrypt
rsa_decrypt <- function(data, key = my_key(), password = readline){
  stopifnot(inherits(key, "rsa"))
  sk <- read_key(key, password)
  stopifnot(is.raw(data))
  .Call(R_rsa_decrypt, data, sk)
}
