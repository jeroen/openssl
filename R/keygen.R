#' Generate Key pair
#'
#' The \code{keygen} functions generate a random private key. Use \code{as.list(key)$pubkey}
#' to derive the corresponding public key.
#'
#' @examples key <- keygen_rsa(1024)
#' pubkey <- as.list(key)$pubkey
#' @export
#' @rdname keygen
#' @useDynLib openssl R_keygen_rsa
keygen_rsa <- function(bits = 2048){
  key <- .Call(R_keygen_rsa, bits)
  structure(key, class = c("key", "rsa"))
}

#' @export
#' @rdname keygen
#' @useDynLib openssl R_keygen_dsa
keygen_dsa <- function(bits = 2048){
  key <- .Call(R_keygen_dsa, bits)
  structure(key, class = c("key", "dsa"))
}

#' @export
#' @rdname keygen
#' @useDynLib openssl R_keygen_ecdsa
keygen_ecdsa <- function(curve = c("P-256", "P-384", "P-521")){
  key <- .Call(R_keygen_ecdsa, curve)
  structure(key, class = c("key", "ecdsa"))
}
