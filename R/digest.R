#' Digest a string
#'
#' The \code{digest_string} function creates a raw hash from a single string.
#' The \code{digest} function is a vectorised version that creates digest strings
#' from many strings at once.
#'
#' @rdname digest
#' @useDynLib openssl R_digest_string
#' @param x strings to digest
#' @param algo digest algorithm, e.g. 'md5' 'sha1', 'sha256', etc.
#' @param string converts output value into a string (TRUE/FALSE)
#' @export
#' @references OpenSSL manual: \url{https://www.openssl.org/docs/crypto/EVP_DigestInit.html}
#' @examples openssl::digest("foo", "md5")
#' digest::digest("foo", "md5", serialize = FALSE)
digest <- function(x, algo){
  vapply(x, digest_string, character(1), algo = algo, string = TRUE, USE.NAMES = FALSE)
}

#' @rdname digest
#' @export
digest_string <- function(x, algo, string = FALSE){
  .Call(R_digest_string, as.character(x), as.character(algo), as.logical(string))
}
