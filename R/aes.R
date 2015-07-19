#' AES encryption
#'
#' Encrypt and decrypt data with a symmetric key using the AES block
#' cipher in CBC mode.
#'
#' @export
#' @rdname aes_cbc
#' @name aes_cbc
#' @param x raw vector with data to encrypt or decrypt
#' @param key secret key. Must be raw vector of length 16, 24 or 32; typically a hash of a secret
#' @param iv initialization vector. Must be raw vector of length 16 (aes block size) or NULL
#' @examples # aes-256 requires 32 byte key
#' password <- charToRaw("supersecret")
#' key <- sha256(password)
#'
#' # symmetric encryption uses same key for decryption
#' x <- serialize(iris, NULL)
#' y <- aes_cbc_encrypt(x, key = key)
#' x2 <- aes_cbc_decrypt(y, key = key)
#' identical(x, x2)
aes_cbc_encrypt <- function(x, key, iv = rand_bytes(16)){
  out <- aes_cbc(x, key, iv, TRUE)
  structure(out, iv = iv)
}

#' @export
#' @rdname aes_cbc
aes_cbc_decrypt <- function(x, key, iv = attr(x, "iv")){
  aes_cbc(x, key, iv, FALSE);
}

#' @useDynLib openssl R_aes_cbc
aes_cbc <- function(x, key, iv = NULL, encrypt){
  if(is.null(iv)){
    iv <- as.raw(rep(0, 16))
  }
  stopifnot(is.raw(x))
  stopifnot(is.raw(key))
  stopifnot(is.raw(iv))
  stopifnot(is.logical(encrypt))
  .Call(R_aes_cbc, x, key, iv, encrypt)
}
