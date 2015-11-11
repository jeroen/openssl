#' Envelope encryption
#'
#' High level procedures for public key encryption.
#'
#' Under the hood, \code{\link{encrypt_envelope}} generates a random IV and session-key
#' to encrypt the \code{data} with the \code{\link{aes_cbc}} cipher. It then encrypts the
#' session-key with the provided RSA public key (see \code{\link{rsa_encrypt}}) and returns
#' this encrypted session key along with the IV and ciphertext. Each of these outputs is
#' required to decrypt the data from the corresponding private key.
#'
#' @useDynLib openssl R_envelope_encrypt
#' @aliases envelope
#' @references \url{https://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope}
#' @export
#' @rdname encrypt_envelope
#' @inheritParams signature_create
#' @param iv 16 byte raw vector returned by \code{encrypt_envelope}.
#' @param session raw vector with encrypted session key as returned by \code{encrypt_envelope}.
#' @examples # Requires RSA key
#' key <- rsa_keygen()
#' pubkey <- as.list(key)$pubkey
#' msg <- serialize(iris, NULL)
#'
#' # Encrypt
#' out <- encrypt_envelope(msg, pubkey)
#' str(out)
#'
#' # Decrypt
#' orig <- decrypt_envelope(out$data, out$iv, out$session, key)
#' stopifnot(identical(msg, orig))
encrypt_envelope <- function(data, pubkey = my_pubkey()){
  pk <- read_pubkey(pubkey)
  data <- path_or_raw(data)
  out <- .Call(R_envelope_encrypt, data, pk)
  structure(out, names = c("iv", "session", "data"))
}

#' @useDynLib openssl R_envelope_decrypt
#' @export
#' @rdname encrypt_envelope
decrypt_envelope <- function(data, iv, session, key = my_key(), password){
  sk <- read_key(key, password = password)
  stopifnot(is.raw(iv))
  stopifnot(is.raw(session))
  data <- path_or_raw(data)
  .Call(R_envelope_decrypt, data, iv, session, sk)
}
