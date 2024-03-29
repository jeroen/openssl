#' Envelope encryption
#'
#' An [envelope](https://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope)
#' contains ciphertext along with an encrypted session key and optionally and initialization
#' vector. The [encrypt_envelope()] generates a random IV and session-key which is
#' used to encrypt the `data` with [`AES()`][openssl::aes_cbc] stream cipher. The
#' session key itself is encrypted using the given RSA key (see [rsa_encrypt()]) and
#' stored or sent along with the encrypted data. Each of these outputs is required to decrypt
#' the data with the corresponding private key.
#'
#' @useDynLib openssl R_envelope_encrypt
#' @aliases envelope
#' @references <https://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope>
#' @export
#' @rdname encrypt_envelope
#' @inheritParams signature_create
#' @param iv 16 byte raw vector returned by `encrypt_envelope`.
#' @param session raw vector with encrypted session key as returned by `encrypt_envelope`.
#' @examples # Requires RSA key
#' key <- rsa_keygen()
#' pubkey <- key$pubkey
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
  stopifnot(inherits(pk, "rsa"))
  data <- path_or_raw(data)
  out <- .Call(R_envelope_encrypt, data, pk)
  structure(out, names = c("iv", "session", "data"))
}

#' @useDynLib openssl R_envelope_decrypt
#' @export
#' @rdname encrypt_envelope
decrypt_envelope <- function(data, iv, session, key = my_key(), password){
  sk <- read_key(key, password = password)
  stopifnot(inherits(sk, "rsa"))
  stopifnot(is.raw(iv))
  stopifnot(is.raw(session))
  data <- path_or_raw(data)
  .Call(R_envelope_decrypt, data, iv, session, sk)
}
