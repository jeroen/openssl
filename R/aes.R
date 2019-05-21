#' Symmetric AES encryption
#'
#' Low-level symmetric encryption/decryption using the AES block cipher in CBC mode.
#' The key is a raw vector, for example a hash of some secret. When no shared
#' secret is available, a random key can be used which is exchanged via an
#' asymmetric protocol such as RSA. See \code{\link{rsa_encrypt}} for a worked example
#' or \code{\link{encrypt_envelope}} for a high-level wrapper combining AES and RSA.
#'
#' @export
#' @rdname aes_cbc
#' @name aes_cbc
#' @param length how many bytes to generate. Usually 16 (128-bit) or 12 (92-bit) for \code{aes_gcm}
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
aes_gcm_encrypt <- function(data, key, iv = rand_bytes(12)){
  aes_encrypt(data, key, iv, "gcm")
}

#' @export
#' @rdname aes_cbc
aes_gcm_decrypt <- function(data, key, iv = attr(data, "iv")){
  aes_decrypt(data, key, iv, "gcm")
}

aes_encrypt <- function(data, key, iv, mode){
  data <- path_or_raw(data)
  if(!is.raw(data))
    stop("The 'data' must path to a file or raw vector")
  out <- aes_any(data, key, iv, TRUE, mode)
  structure(out, iv = iv)
}

aes_decrypt <- function(data, key, iv, mode){
  data <- path_or_raw(data)
  if(!is.raw(data))
    stop("The 'data' must be raw vector")
  aes_any(data, key, iv, FALSE, mode)
}

#' @useDynLib openssl R_aes_any
aes_any <- function(x, key, iv = NULL, encrypt, mode){
  if(is.null(iv)){
    iv <- as.raw(rep(0, 16))
  }
  stopifnot(is.raw(x))
  stopifnot(is.raw(key))
  stopifnot(is.raw(iv))
  stopifnot(is.logical(encrypt))
  stopifnot(is.character(mode))
  cipher <- paste("aes", length(key) * 8, mode, sep = "-")
  .Call(R_aes_any, x, key, iv, encrypt, cipher)
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
