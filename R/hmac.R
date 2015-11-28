#' HMAC
#'
#' HMAC is a MAC (message authentication code), i.e. a keyed hash function.
#'
#' @export
#' @param data raw vector with data to sign
#' @param key raw vector with secret key
#' @param hash which digest function to use
#' @useDynLib openssl R_hmac
#' @references \url{https://www.openssl.org/docs/manmaster/crypto/hmac.html}
#' @examples key <- rand_bytes(16)
#' msg <- serialize(iris, NULL)
#' hmac(msg, key, "md5")
#' hmac(msg, key, "sha1")
hmac <- function(data, key, hash = c("md5", "sha1", "sha256", "sha512")) {
  mdlen <- switch(match.arg(hash), md5 = 16, sha1 = 20, sha256 = 32, sha512 = 64)
  stopifnot(is.raw(data))
  stopifnot(is.raw(key))
  .Call(R_hmac, data, key, mdlen)
}
