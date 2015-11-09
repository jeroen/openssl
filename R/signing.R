#' Signatures
#'
#' Sign and verify a message digest. DSA and ECDSA keys only support SHA1
#' and SHA256 signatures.
#'
#' @export
#' @rdname signatures
#' @param hash string or raw vector with md5, sha1 or sha256 hash
#' @param key private key or file path. See \code{\link{read_key}}.
#' @param pubkey public key or file path. See \code{\link{read_pubkey}}.
#' @param sig path or raw vector with signature data
#' @param password string or a function to read protected keys.
#' @examples \dontrun{
#' hash <- sha256(system.file("DESCRIPTION"))
#' sig <- sha256_sign(hash)
#' sha256_verify(hash, sig)
#'
#' hash <- sha1(serialize(iris, NULL))
#' sig <- sha1_sign(hash)
#' sha1_verify(hash, sig)
#' }
md5_sign <- function(hash, key, password = readline){
  key <- read_key(key, password = password)
  if(is_hexraw(hash))
    hash <- hex_to_raw(hash)
  if(!is.raw(hash) || length(hash) != 16)
    stop("hash must be md5 digest")
  hash_sign(hash, key)
}

#' @export
#' @rdname signatures
sha1_sign <- function(hash, key, password = readline){
  key <- read_key(key, password = password)
  if(is_hexraw(hash))
    hash <- hex_to_raw(hash)
  if(!is.raw(hash) || length(hash) != 20)
    stop("hash must be sha1 digest")
  hash_sign(hash, key)
}

#' @export
#' @rdname signatures
sha256_sign <- function(hash, key, password = readline){
  key <- read_key(key, password = password)
  if(is_hexraw(hash))
    hash <- hex_to_raw(hash)
  if(!is.raw(hash) || length(hash) != 32)
    stop("hash must be sha256 digest")
  hash_sign(hash, key)
}

#' @export
#' @rdname signatures
md5_verify <- function(hash, sig, pubkey){
  pubkey <- read_pubkey(pubkey)
  if(is_hexraw(hash))
    hash <- hex_to_raw(hash)
  if(!is.raw(hash) || length(hash) != 16)
    stop("hash must be md5 digest")
  hash_verify(hash, sig, pubkey)
}

#' @export
#' @rdname signatures
sha1_verify <- function(hash, sig, pubkey){
  pubkey <- read_pubkey(pubkey)
  if(is_hexraw(hash))
    hash <- hex_to_raw(hash)
  if(!is.raw(hash) || length(hash) != 20)
    stop("hash must be sha1 digest")
  hash_verify(hash, sig, pubkey)
}

#' @export
#' @rdname signatures
sha256_verify <- function(hash, sig, pubkey){
  pubkey <- read_pubkey(pubkey)
  if(is_hexraw(hash))
    hash <- hex_to_raw(hash)
  if(!is.raw(hash) || length(hash) != 32)
    stop("hash must be sha256 digest")
  hash_verify(hash, sig, pubkey)
}

#' @useDynLib openssl R_hash_sign
hash_sign <- function(hash, key){
  .Call(R_hash_sign, hash, key)
}

#' @useDynLib openssl R_hash_verify
hash_verify <- function(hash, sig, pubkey){
  .Call(R_hash_verify, hash, sig, pubkey)
}
