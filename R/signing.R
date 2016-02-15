#' Signatures
#'
#' Sign and verify a message digest. RSA supports both MD5 and SHA signatures
#' whereas DSA and EC keys only support SHA.
#'
#' @export
#' @rdname signatures
#' @param data raw data vector or file path for message to be signed.
#' If \code{hash == NULL} then \code{data} must be a hash string or raw vector.
#' @param hash the digest function to use. Must be one of \code{\link{md5}},
#' \code{\link{sha1}}, \code{\link{sha256}}, \code{\link{sha512}} or \code{NULL}.
#' @param key private key or file path. See \code{\link{read_key}}.
#' @param pubkey public key or file path. See \code{\link{read_pubkey}}.
#' @param sig raw vector or file path for the signature data.
#' @param password string or a function to read protected keys. See \code{\link{read_key}}.
#' @examples # Generate a keypair
#' key <- rsa_keygen()
#' pubkey <- as.list(key)$pubkey
#'
#' # Sign a file
#' data <- system.file("DESCRIPTION")
#' sig <- signature_create(data, key = key)
#' stopifnot(signature_verify(data, sig, pubkey = pubkey))
#'
#' # Sign raw data
#' data <- serialize(iris, NULL)
#' sig <- signature_create(data, sha256, key = key)
#' stopifnot(signature_verify(data, sig, sha256, pubkey = pubkey))
#'
#' # Sign a hash
#' md <- md5(data)
#' sig <- signature_create(md, hash = NULL, key = key)
#' stopifnot(signature_verify(md, sig, hash = NULL, pubkey = pubkey))
signature_create <- function(data, hash = sha1, key = my_key(), password = askpass){
  data <- path_or_raw(data)
  sk <- read_key(key, password = password)
  md <- if(is.null(hash)) parse_hash(data) else hash(data)
  if(!is.raw(md) || !(length(md) %in% c(16, 20, 28, 32, 48, 64)))
    stop("data must be md5, sha1, or sha2 digest")
  hash_sign(md, sk)
}

#' @export
#' @rdname signatures
signature_verify <- function(data, sig, hash = sha1, pubkey = my_pubkey()){
  data <- path_or_raw(data)
  sig <- path_or_raw(sig)
  pk <- read_pubkey(pubkey)
  md <- if(is.null(hash)) parse_hash(data) else hash(data)
  if(!is.raw(md) || !(length(md) %in% c(16, 20, 28, 32, 48, 64)))
    stop("data must be md5, sha1, or sha2 digest")
  hash_verify(md, sig, pk)
}

#' @useDynLib openssl R_hash_sign
hash_sign <- function(hash, key){
  .Call(R_hash_sign, hash, key)
}

#' @useDynLib openssl R_hash_verify
hash_verify <- function(hash, sig, pubkey){
  .Call(R_hash_verify, hash, sig, pubkey)
}
