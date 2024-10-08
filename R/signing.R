#' Signatures
#'
#' Sign and verify a message digest. RSA supports both MD5 and SHA signatures
#' whereas DSA and EC keys only support SHA. ED25591 can sign any payload so you can
#' set `hash` to `NULL` to sign the raw input data.
#'
#' The `ecdsa_parse` and `ecdsa_write` functions convert (EC)DSA signatures
#' between the conventional DER format and the raw `(r,s)` bignum pair. Most
#' users won't need this, it is mostly here to support the JWT format (which does not
#' use DER).
#'
#' @export
#' @aliases signatures
#' @rdname signatures
#' @param data raw data vector or file path for message to be signed.
#' If `hash == NULL` then `data` must be a hash string or raw vector.
#' @param hash the digest function to use. Must be one of [md5()],
#' [sha1()], [sha256()], [sha512()] or `NULL`.
#' @param key private key or file path. See [read_key()].
#' @param pubkey public key or file path. See [read_pubkey()].
#' @param sig raw vector or file path for the signature data.
#' @param password string or a function to read protected keys. See [read_key()].
#' @examples # Generate a keypair
#' key <- rsa_keygen()
#' pubkey <- key$pubkey
#'
#' # Sign a file
#' data <- system.file("DESCRIPTION")
#' sig <- signature_create(data, sha256, key = key)
#' stopifnot(signature_verify(data, sig, sha256, pubkey = pubkey))
#'
#' # Sign raw data
#' data <- serialize(iris, NULL)
#' sig <- signature_create(data, sha256, key = key)
#' stopifnot(signature_verify(data, sig, sha256, pubkey = pubkey))
#'
#' # Sign a hash
#' md <- md5(data)
#' sig <- signature_create(md, hash = sha256, key = key)
#' stopifnot(signature_verify(md, sig, hash = sha256, pubkey = pubkey))
signature_create <- function(data, hash = sha1, key = my_key(), password = askpass){
  data <- path_or_raw(data)
  sk <- read_key(key, password = password)
  md <- if(is.null(hash)) parse_hash(data) else hash(data)
  if(inherits(sk, "ed25519"))
    return(data_sign(md, sk))
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
  if(inherits(pk, "ed25519"))
    return(data_verify(md, sig, pk))
  if(!is.raw(md) || !(length(md) %in% c(16, 20, 28, 32, 48, 64)))
    stop("data must be md5, sha1, or sha2 digest")
  hash_verify(md, sig, pk)
}

#' @export
#' @rdname signatures
#' @useDynLib openssl R_parse_ecdsa
#' @examples #
#' # ECDSA example
#' data <- serialize(iris, NULL)
#' key <- ec_keygen()
#' pubkey <- key$pubkey
#' sig <- signature_create(data, sha256, key = key)
#' stopifnot(signature_verify(data, sig, sha256, pubkey = pubkey))
#'
#' # Convert signature to (r, s) parameters and then back
#' params <- ecdsa_parse(sig)
#' out <- ecdsa_write(params$r, params$s)
#' identical(sig, out)
ecdsa_parse <- function(sig){
  if(length(sig) > 150)
    warning("You can only parse DSA and ECDSA signatures. This looks like an RSA signature.")
  .Call(R_parse_ecdsa, sig)
}

#' @export
#' @rdname signatures
#' @useDynLib openssl R_write_ecdsa
#' @param r bignum value for r parameter
#' @param s bignum value for s parameter
ecdsa_write <- function(r, s){
  stopifnot(is.raw(r), is.raw(s))
  class(r) <- "bignum"
  class(s) <- "bignum"
  .Call(R_write_ecdsa, r, s)
}

#' @useDynLib openssl R_hash_sign
hash_sign <- function(hash, key){
  .Call(R_hash_sign, hash, key)
}

#' @useDynLib openssl R_hash_verify
hash_verify <- function(hash, sig, pubkey){
  .Call(R_hash_verify, hash, sig, pubkey)
}
