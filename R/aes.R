#' AES encryption
#'
#' Symmetric encryption/decryption using the AES block cipher in CBC mode.
#' When a existing shared secret is available, the key can be a cryptographic
#' hash of the secret. When no shared secret is available, a random temporary
#' key can be used which is exchanged via an asymettric protocol such as RSA.
#' See \code{\link{rsa_encrypt}} for a worked example.
#'
#' @export
#' @rdname aes_cbc
#' @name aes_cbc
#' @param msg raw vector or path to file with data to encrypt
#' @param ciphertext raw vector containing the encrypted message
#' @param key secret key. Must be raw vector of length 16, 24 or 32, e.g.
#' the sha256 hash of a secret passphrase
#' @param iv initialization vector. Must be raw vector of length 16 (aes
#' block size) or NULL. This part is not secret but should be random.
#' @examples # aes-256 requires 32 byte key
#' passphrase <- charToRaw("This is super secret")
#' key <- sha256(passphrase)
#'
#' # symmetric encryption uses same key for decryption
#' x <- serialize(iris, NULL)
#' y <- aes_cbc_encrypt(x, key = key)
#' x2 <- aes_cbc_decrypt(y, key = key)
#' stopifnot(identical(x, x2))
aes_cbc_encrypt <- function(msg, key, iv = rand_bytes(16)){
  if(is.character(msg) && length(msg) == 1 && file.exists(msg)){
    msg <- readBin(msg, raw(), file.info(msg)$size)
  }
  if(!is.raw(msg))
    stop("The 'msg' must path to a file or raw vector")
  out <- aes_cbc(msg, key, iv, TRUE)
  structure(out, iv = iv)
}

#' @export
#' @rdname aes_cbc
aes_cbc_decrypt <- function(ciphertext, key, iv = attr(ciphertext, "iv")){
  if(!is.raw(ciphertext))
    stop("The 'ciphertext' must be raw vector")
  aes_cbc(ciphertext, key, iv, FALSE);
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
