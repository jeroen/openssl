#' AES encryption
#'
#' Encrypt and decrypt data with a symmetric key using the AES block
#' cipher in CBC mode.
#'
#' @export
#' @useDynLib openssl R_aes_cbc
#' @param x raw vector with data to encrypt/decrypt
#' @param key raw vector of length 16, 24 or 32, e.g. a password hash
#' @param iv a random initialization vector of length 16
#' @examples password <- charToRaw("supersecret")
#' x <- serialize(iris, NULL)
#' y <- aes_cbc_encrypt(x, key = sha256(password))
#' x2 <- aes_cbc_decrypt(y, key = sha256(password))
#' identical(x, x2)
aes_cbc_encrypt <- function(x, key, iv = rand_bytes(16)){
  stopifnot(is.raw(x))
  stopifnot(is.raw(key))
  stopifnot(is.raw(iv))
  out <- .Call(R_aes_cbc, x, key, iv, TRUE)
  structure(out, iv = iv)
}

#' @export
#' @useDynLib openssl R_aes_cbc
aes_cbc_decrypt <- function(x, key, iv = attr(x, "iv")){
  stopifnot(is.raw(x))
  stopifnot(is.raw(key))
  stopifnot(is.raw(iv))
  .Call(R_aes_cbc, x, key, iv, FALSE);
}
