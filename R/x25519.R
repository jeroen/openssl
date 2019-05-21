#' Curve25519
#'
#' Curve25519 is a recently added low-level algorithm that can be used both for
#' diffie-hellman (called X25519) and for signatures (called ED25519). Note that
#' these functions are only available when building against version 1.1.1 or
#' newer of the openssl library. The same functions are also available in the
#' sodium R package.
#'
#' @export
#' @name curve25519
#' @rdname curve25519
#' @param x a 32 byte raw vector with (pub)key data
#' @examples # Generate a keypair
#' if(openssl_config()$x25519){
#' key <- ed25519_keygen()
#' pubkey <- as.list(key)$pubkey
#'
#' # Sign message
#' msg <- serialize(iris, NULL)
#' sig <- ed25519_sign(msg, key)
#'
#' # Verify the signature
#' ed25519_verify(msg, sig, pubkey)
#'
#' # Diffie Hellman example:
#' key1 <- x25519_keygen()
#' key2 <- x25519_keygen()
#'
#' # Both parties can derive the same secret
#' x25519_diffie_hellman(key1, key2$pubkey)
#' x25519_diffie_hellman(key2, key1$pubkey)
#'
#' # Import/export sodium keys
#' rawkey <- sodium::sig_keygen()
#' rawpubkey <- sodium::sig_pubkey(rawkey)
#' key <- read_ed25519_key(rawkey)
#' pubkey <- read_ed25519_pubkey(rawpubkey)
#'
#' # To get the raw key data back for use in sodium
#' as.list(key)$data
#' as.list(pubkey)$data
#' }
read_ed25519_key <- function(x){
  stopifnot(is.raw(x))
  if(length(x) == 64)
    x <- utils::head(x, 32L)
  stopifnot(length(x) == 32)
  structure(read_raw_key_ed25519(x), class = c("key", "ed25519"))
}

#' @export
#' @rdname curve25519
read_ed25519_pubkey <- function(x){
  stopifnot(is.raw(x))
  stopifnot(length(x) == 32)
  structure(read_raw_pubkey_ed25519(x), class = c("pubkey", "ed25519"))
}

#' @export
#' @rdname curve25519
read_x25519_key <- function(x){
  stopifnot(is.raw(x))
  if(length(x) == 64)
    x <- utils::head(x, 32L)
  stopifnot(length(x) == 32)
  structure(read_raw_key_x25519(x), class = c("key", "x25519"))
}

#' @export
#' @rdname curve25519
read_x25519_pubkey <- function(x){
  stopifnot(is.raw(x))
  stopifnot(length(x) == 32)
  structure(read_raw_pubkey_x25519(x), class = c("pubkey", "x25519"))
}

#' @export
#' @rdname curve25519
#' @param key private key as returned by \code{read_ed25519_key} or \code{ed25519_keygen}
ed25519_sign <- function(data, key){
  stopifnot(is.raw(data))
  key <- read_key(key)
  stopifnot(inherits(key, 'ed25519'))
  data_sign(data, key)
}

#' @export
#' @rdname curve25519
#' @param data raw vector with data to sign or verify
#' @param sig raw vector of length 64 with signature as returned by \code{ed25519_sign}
#' @param pubkey public key as returned by \code{read_ed25519_pubkey} or \code{key$pubkey}
ed25519_verify <- function(data, sig, pubkey){
  stopifnot(is.raw(data))
  stopifnot(is.raw(sig))
  if(length(sig) != 64)
    stop("Signature must have length 64")
  pubkey <- read_pubkey(pubkey)
  stopifnot(inherits(pubkey, 'ed25519'))
  data_verify(data, sig, pubkey)
}

#' @export
#' @rdname curve25519
x25519_diffie_hellman <- function(key, pubkey){
  key <- read_key(key)
  pubkey <- read_pubkey(pubkey)
  stopifnot(inherits(key, 'x25519'))
  stopifnot(inherits(pubkey, 'x25519'))
  ec_dh(key, pubkey)
}

#' @useDynLib openssl R_read_raw_key_ed25519
read_raw_key_ed25519 <- function(x){
  .Call(R_read_raw_key_ed25519, x)
}

#' @useDynLib openssl R_read_raw_pubkey_ed25519
read_raw_pubkey_ed25519 <- function(x){
  .Call(R_read_raw_pubkey_ed25519, x)
}

#' @useDynLib openssl R_read_raw_key_x25519
read_raw_key_x25519 <- function(x){
  .Call(R_read_raw_key_x25519, x)
}

#' @useDynLib openssl R_read_raw_pubkey_x25519
read_raw_pubkey_x25519 <- function(x){
  .Call(R_read_raw_pubkey_x25519, x)
}

#' @useDynLib openssl R_write_raw_key
write_raw_key <- function(x){
  .Call(R_write_raw_key, x)
}

#' @useDynLib openssl R_write_raw_pubkey
write_raw_pubkey <- function(x){
  .Call(R_write_raw_pubkey, x)
}

#' @useDynLib openssl R_data_sign
data_sign <- function(data, key){
  .Call(R_data_sign, data, key)
}

#' @useDynLib openssl R_data_verify
data_verify <- function(data, sig, pubkey){
  .Call(R_data_verify, data, sig, pubkey)
}
