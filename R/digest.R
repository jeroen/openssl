#' Hash a string
#'
#' The \code{rawhash} function creates a raw hash from a single string.
#' The \code{hash} function is a vectorised version that creates digest strings
#' from many strings at once.
#'
#' @rdname hash
#' @useDynLib openssl R_digest_raw R_digest R_openssl_init R_openssl_cleanup
#' @param x strings to digest
#' @param algo digest algorithm, e.g. 'md5' 'sha1', 'sha256', etc.
#' @export
#' @references OpenSSL manual: \url{https://www.openssl.org/docs/crypto/EVP_DigestInit.html}
#' @examples library(digest)
#' hash("foo", "md5")
#' digest("foo", "md5", serialize = FALSE)
hash <- function(x, algo){
  .Call(R_digest, as.character(x), as.character(algo))
}

#' @rdname hash
#' @export
rawhash <- function(x, algo){
  .Call(R_digest_raw, as.character(x), as.character(algo))
}
