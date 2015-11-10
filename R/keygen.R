#' Generate Key pair
#'
#' The \code{keygen} functions generate a random private key. Use \code{as.list(key)$pubkey}
#' to derive the corresponding public key.
#'
#' @export
#' @rdname keygen
#' @name keygen
#' @useDynLib openssl R_keygen_rsa
#' @param bits bitsize of the generated RSA/DSA key
#' @param curve which NIST curve to use
#' @examples key <- rsa_keygen()
#' pubkey <- as.list(key)$pubkey
rsa_keygen <- function(bits = 2048){
  key <- .Call(R_keygen_rsa, as.integer(bits))
  structure(key, class = c("key", "rsa"))
}

#' @export
#' @rdname keygen
#' @useDynLib openssl R_keygen_dsa
dsa_keygen <- function(bits = 1024){
  key <- .Call(R_keygen_dsa, as.integer(bits))
  structure(key, class = c("key", "dsa"))
}

#' @export
#' @rdname keygen
#' @useDynLib openssl R_keygen_ecdsa
ec_keygen <- function(curve = c("P-256", "P-384", "P-521")){
  key <- .Call(R_keygen_ecdsa, match.arg(curve))
  structure(key, class = c("key", "ecdsa"))
}
