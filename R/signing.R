#' Sign and verify
#'
#' Create and verify RSA signatures.
#'
#' @export
#' @rdname signing
#' @name signing
#' @param hash string or raw vector with md5, sha1 or sha256 hash
#' @param key file path or raw/character vector with RSA private key
#' @param pubkey file path or raw/character vector with RSA public key
#' @param sig raw vector with signature data
#' @param password either a hardcoded string or a callback function that
#' returns a string. Only required if key is protected with a passphrase.
#' @useDynLib openssl R_rsa_sign
#' @examples hash <- sha256(system.file("DESCRIPTION"))
#' sig <- rsa_sign(hash)
#' rsa_verify(hash, sig)
#'
#' hash <- sha1(serialize(iris, NULL))
#' sig <- rsa_sign(hash)
#' rsa_verify(hash, sig)
#'
#' hash <- md5("i like cookies")
#' sig <- rsa_sign(hash)
#' rsa_verify(hash, sig)
rsa_sign <- function(hash, key = "~/.ssh/id_rsa", password = readline) {
  if(is_hexraw(hash))
    hash <- hex_to_raw(hash)
  if(!is.raw(hash) || !(length(hash) %in% c(16, 20, 32)))
    stop("Hash must be raw vector or string with md5, sha1 or sha256 value")
  key <- read_pem(key, password)
  if(!inherits(key, "rsa.private"))
    stop("key must be rsa private key")
  .Call(R_rsa_sign, hash, hash_type(hash), key)
}

#' @export
#' @rdname signing
#' @useDynLib openssl R_rsa_verify
rsa_verify <- function(hash, sig, pubkey = "~/.ssh/id_rsa.pub"){
  if(is_hexraw(hash))
    hash <- hex_to_raw(hash)
  if(!is.raw(hash) || !(length(hash) %in% c(16, 20, 32)))
    stop("Hash must be raw vector or string with md5, sha1 or sha256 value")
  if(is_hexraw(sig))
    sig <- hex_to_raw(sig)
  if(!is.raw(sig))
    stop("Sig must be raw vector or hex string with signature data")
  key <- read_pem(pubkey)
  if(inherits(key, "rsa.private"))
    key <- priv2pub(key)
  .Call(R_rsa_verify, hash, sig, hash_type(hash), key)
}
