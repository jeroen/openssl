#' Low-level RSA encryption
#'
#' Asymmetric encryption and decryption with RSA. Because RSA can only encrypt messages
#' smaller than the size of the key, it is typically used only for exchanging a random
#' session-key. This session key is used to encipher arbitrary sized data via a stream
#' cipher such as [aes_cbc]. See [encrypt_envelope] or [pkcs7_encrypt] for a high-level
#' wrappers combining RSA and AES in this way.
#'
#' @export
#' @param data raw vector of max 245 bytes (for 2048 bit keys) with data to encrypt/decrypt
#' @param oaep if TRUE, changes padding to EME-OAEP as defined in PKCS #1 v2.0
#' @inheritParams signature_create
#' @rdname rsa_encrypt
#' @aliases rsa encrypt
#' @useDynLib openssl R_rsa_encrypt
#' @examples # Generate test keys
#' key <- rsa_keygen()
#' pubkey <- key$pubkey
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
#' out <- rawToChar(message)
rsa_encrypt <- function(data, pubkey = my_pubkey(), oaep = FALSE){
  pk <- read_pubkey(pubkey)
  stopifnot(inherits(pk, "rsa"))
  stopifnot(is.raw(data))
  oaep <- as.logical(oaep)
  .Call(R_rsa_encrypt, data, pk, oaep)
}

#' @useDynLib openssl R_rsa_decrypt
#' @export
#' @rdname rsa_encrypt
rsa_decrypt <- function(data, key = my_key(), password = askpass, oaep = FALSE){
  sk <- read_key(key, password)
  stopifnot(inherits(sk, "rsa"))
  stopifnot(is.raw(data))
  oaep <- as.logical(oaep)
  .Call(R_rsa_decrypt, data, sk, oaep)
}
