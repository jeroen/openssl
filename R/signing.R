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
#' @param pad padding type. Must be `NULL` (default) or `"pss"`.
#' For RSA keys, `"pss"` enables RSA-PSS padding. For non-RSA keys (ECDSA, DSA,
#' Ed25519, X25519), this is ignored.  RSA-PSS signatures are stochastic,
#' but can still be verified.
#' @param salt_length salt length for RSA-PSS padding. This can be
#' a character string (i.e., `"digest"`, `"auto"`, `"max"`) or an integer.
#' Defaults to `NULL` which is the same as auto salt length
#' (`RSA_PSS_SALTLEN_AUTO`). Only used when `pad = "pss"`.  When verifying,
#' salt_length = "auto" will verify an RSA-PSS signature with any salt length.
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
#' sig <- signature_create(md, hash = sha256, key = key, pad = "pss",
#'                         salt_length = "max")
#' stopifnot(signature_verify(md, sig, hash = sha256, pubkey = pubkey,
#'                            pad = "pss"))
signature_create <- function(data, hash = sha1, key = my_key(), password = askpass, pad = NULL, salt_length = NULL){
  data <- path_or_raw(data)
  sk <- read_key(key, password = password)
  md <- if(is.null(hash)) parse_hash(data) else hash(data)
  if(inherits(sk, "ed25519"))
    return(data_sign(md, sk))
  if(!is.raw(md) || !(length(md) %in% c(16, 20, 28, 32, 48, 64)))
    stop("data must be md5, sha1, or sha2 digest")
  if(length(pad) == 1 && !pad %in% "pss") stop("pad must be NULL or \"pss\"")
  salt_length <- normalize_pss_saltlen(salt_length)
  hash_sign(md, sk, pad, salt_length)
}

#' @export
#' @rdname signatures
signature_verify <- function(data, sig, hash = sha1, pubkey = my_pubkey(), pad = NULL, salt_length = NULL){
  data <- path_or_raw(data)
  sig <- path_or_raw(sig)
  pk <- read_pubkey(pubkey)
  md <- if(is.null(hash)) parse_hash(data) else hash(data)
  if(inherits(pk, "ed25519"))
    return(data_verify(md, sig, pk))
  if(!is.raw(md) || !(length(md) %in% c(16, 20, 28, 32, 48, 64)))
    stop("data must be md5, sha1, or sha2 digest")
  if(length(pad) == 1 && !pad %in% "pss") stop("pad must be NULL or \"pss\"")
  salt_length <- normalize_pss_saltlen(salt_length)
  hash_verify(md, sig, pk, pad, salt_length)
}

normalize_pss_saltlen <- function(salt_length) {
  if (length(salt_length) == 0) return(NULL) # use OpenSSL default (AUTO)
  if (length(salt_length) > 1) stop('salt_length must be NULL or length 1')
  if (is.character(salt_length)) {
    sl <- switch(salt_length,
                 digest = -1L,
                 auto   = -2L,
                 max    = -3L,
                 stop("Invalid salt_length: must be 'max', 'auto', 'digest', or an integer")
    )
    return(sl)
  }
  as.integer(salt_length)
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
hash_sign <- function(hash, key, pad = NULL, salt_length = NULL){
  .Call(R_hash_sign, hash, key, pad, salt_length)
}

#' @useDynLib openssl R_hash_verify
hash_verify <- function(hash, sig, pubkey, pad = NULL, salt_length = NULL){
  .Call(R_hash_verify, hash, sig, pubkey, pad, salt_length)
}
