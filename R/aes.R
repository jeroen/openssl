#' Symmetric AES encryption
#'
#' Low-level symmetric encryption/decryption using the AES block cipher in CBC mode.
#' The key is a raw vector, for example a hash of some secret. When no shared
#' secret is available, a random key can be used which is exchanged via an
#' asymettric protocol such as RSA. See \code{\link{rsa_encrypt}} for a worked example
#' or \code{\link{encrypt_envelope}} for a high-level wrapper combining AES and RSA.
#'
#' @export
#' @rdname aes_cbc
#' @name aes_cbc
#' @param data raw vector or path to file with data to encrypt or decrypt
#' @param key raw vector of length 16, 24 or 32, e.g. the hash of a shared secret
#' @param iv raw vector of length 16 (aes block size) or NULL. The initialization vector
#' is not secret but should be random
#' @examples # aes-256 requires 32 byte key
#' passphrase <- charToRaw("This is super secret")
#' key <- sha256(passphrase)
#'
#' # symmetric encryption uses same key for decryption
#' x <- serialize(iris, NULL)
#' y <- aes_cbc_encrypt(x, key = key)
#' x2 <- aes_cbc_decrypt(y, key = key)
#' stopifnot(identical(x, x2))
aes_cbc_encrypt <- function(data, key, iv = rand_bytes(16)){
  data <- path_or_raw(data)
  if(!is.raw(data))
    stop("The 'data' must path to a file or raw vector")
  out <- aes_cbc(data, key, iv, TRUE)
  structure(out, iv = iv)
}

#' @export
#' @rdname aes_cbc
aes_cbc_decrypt <- function(data, key, iv = attr(data, "iv")){
  data <- path_or_raw(data)
  if(!is.raw(data))
    stop("The 'data' must be raw vector")
  aes_cbc(data, key, iv, FALSE);
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
