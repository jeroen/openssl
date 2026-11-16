#' Symmetric AES encryption
#'
#' Low-level symmetric encryption/decryption using the AES block cipher in CBC mode.
#' The key is a raw vector, for example a hash of some secret. When no shared
#' secret is available, a random key can be used which is exchanged via an
#' asymmetric protocol such as RSA. See [rsa_encrypt()] for a worked example
#' or [encrypt_envelope()] for a high-level wrapper combining AES and RSA.
#'
#' @export
#' @rdname aes_cbc
#' @name aes_cbc
#' @param length how many bytes to generate. Usually 16 (128-bit) or 12 (92-bit) for `aes_gcm`
#' @param data raw vector or path to file with data to encrypt or decrypt
#' @param key raw vector of length 16, 24 or 32, e.g. the hash of a shared secret
#' @param iv raw vector of length 16 (aes block size) or NULL. The initialization vector
#' is not secret but should be random
#' @param tag raw vector with the authentication tag for `aes_gcm`, which is
#' returned as an attribute by `aes_gcm_encrypt`. If `NULL`, the data is not verified.
#' @param aad optional additional authenticated data for `aes_gcm`: a raw vector or
#' string that is authenticated by the tag but not encrypted. The same value must be
#' supplied when decrypting.
#' @examples # aes-256 requires 32 byte key
#' passphrase <- charToRaw("This is super secret")
#' key <- sha256(passphrase)
#'
#' # symmetric encryption uses same key for decryption
#' x <- serialize(iris, NULL)
#' y <- aes_cbc_encrypt(x, key = key)
#' x2 <- aes_cbc_decrypt(y, key = key)
#' stopifnot(identical(x, x2))
aes_ctr_encrypt <- function(data, key, iv = rand_bytes(16)){
  aes_encrypt(data, key, iv, "ctr")
}

#' @export
#' @rdname aes_cbc
aes_ctr_decrypt <- function(data, key, iv = attr(data, "iv")){
  aes_decrypt(data, key, iv, "ctr")
}

#' @export
#' @rdname aes_cbc
aes_cbc_encrypt <- function(data, key, iv = rand_bytes(16)){
  aes_encrypt(data, key, iv, "cbc")
}

#' @export
#' @rdname aes_cbc
aes_cbc_decrypt <- function(data, key, iv = attr(data, "iv")){
  aes_decrypt(data, key, iv, "cbc")
}

#' @export
#' @rdname aes_cbc
aes_gcm_encrypt <- function(data, key, iv = rand_bytes(12), aad = NULL){
  aes_encrypt(data, key, iv, "gcm", aad)
}

#' @export
#' @rdname aes_cbc
aes_gcm_decrypt <- function(data, key, iv = attr(data, "iv"), tag = attr(data, "tag"), aad = NULL){
  if(is.null(tag))
    warning("No authentication tag supplied: aes-gcm data is decrypted without verification")
  aes_decrypt(data, key, iv, "gcm", tag, aad)
}

aes_encrypt <- function(data, key, iv, mode, aad = NULL){
  data <- path_or_raw(data)
  if(!is.raw(data))
    stop("The 'data' must path to a file or raw vector")
  out <- aes_any(data, key, iv, TRUE, mode, aad = aad)
  structure(out, iv = iv)
}

aes_decrypt <- function(data, key, iv, mode, tag = NULL, aad = NULL){
  data <- path_or_raw(data)
  if(!is.raw(data))
    stop("The 'data' must be raw vector")
  aes_any(data, key, iv, FALSE, mode, tag, aad)
}

#' @useDynLib openssl R_aes_any
aes_any <- function(x, key, iv = NULL, encrypt, mode, tag = NULL, aad = NULL){
  if(is.character(aad)){
    aad <- charToRaw(aad)
  }
  if(is.null(iv)){
    iv <- as.raw(rep(0, 16))
  }
  stopifnot(is.raw(x))
  stopifnot(is.raw(key))
  stopifnot(is.raw(iv))
  stopifnot(is.logical(encrypt))
  stopifnot(is.character(mode))
  stopifnot(is.null(tag) || is.raw(tag))
  stopifnot(is.null(aad) || is.raw(aad))
  cipher <- paste("aes", length(key) * 8, mode, sep = "-")
  .Call(R_aes_any, x, key, iv, encrypt, cipher, tag, aad)
}

#' @rdname aes_cbc
#' @export
aes_keygen <- function(length = 16){
  structure(rand_bytes(length), class = c("aes", "raw"))
}

#' @export
print.aes <- function(x, ...){
  cat("aes", paste(x, collapse = ":"), "\n")
}

#' AES key wrap
#'
#' Encrypt a key with another key (the key-encryption key) using the AES key
#' wrap algorithm from [RFC 3394](https://www.rfc-editor.org/info/rfc3394/).
#' This is used for example by JWE (`A128KW`, `A256KW`). Unwrapping verifies
#' the integrity of the wrapped key.
#'
#' @export
#' @rdname aes_keywrap
#' @param data raw vector with the key to wrap (a multiple of 8 bytes, at least 16)
#' or the wrapped key to unwrap
#' @param key raw vector of length 16, 24 or 32 with the key-encryption key
#' @useDynLib openssl R_aes_keywrap
#' @examples kek <- rand_bytes(32)
#' cek <- rand_bytes(32)
#' wrapped <- aes_keywrap(cek, kek)
#' stopifnot(identical(aes_keyunwrap(wrapped, kek), cek))
aes_keywrap <- function(data, key){
  stopifnot(is.raw(data))
  stopifnot(is.raw(key))
  .Call(R_aes_keywrap, data, key, TRUE)
}

#' @export
#' @rdname aes_keywrap
aes_keyunwrap <- function(data, key){
  stopifnot(is.raw(data))
  stopifnot(is.raw(key))
  .Call(R_aes_keywrap, data, key, FALSE)
}
