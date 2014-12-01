#' @title hash a string
#'
#' @description The \code{rawhash} function creates a raw hash from a single string.
#' The \code{hash} function is a vectorised version that creates digest strings
#' from many strings at once.
#'
#' @rdname hash
#' @useDynLib openssl R_digest_raw R_digest R_openssl_init R_openssl_cleanup
#' @param x a string, or a vector of strings, to hash.
#' @param algo the cryptographic algorithm to apply. Options are "md5", "sha", "sha1",
#' "sha224","sha256", "sha384", "sha512", "ripemd160" and "dss1". See "Details".
#' @param salt whether or not to include a cryptographically strong randomised value (or "salt"),
#' generated with \code{\link{rand_bytes}}, with each string. This salt is consistent
#' within the call to \code{hash}, but inconsistent between runs, allowing you to
#' maintain consistency within a dataset while simultaneously rendering the results
#' incomparable to other datasets with some of the same data points. Set to FALSE by default.
#'
#' @details the \code{hash} family of functions act as a connector to OpenSSL's crypto
#' module, and allow you to cryptographically hash anything that can be coerced to a character
#' vector. The full range of OpenSSL-supported cryptographic functions are available, but they
#' (and we) recommend either "sha256" or "sha512" for sensitive information; while md5 and
#' weaker members of the sha family are probably sufficient for collision-resistant identifiers,
#' cryptographic weaknesses have been directly or indirectly identified in their output.
#'
#' If the intent is to
#' @export
#' @references OpenSSL manual: \url{https://www.openssl.org/docs/crypto/EVP_DigestInit.html}
#' @examples library(digest)
#' hash("foo", "md5")
#' digest("foo", "md5", serialize = FALSE)
hash <- function(x, algo, salt = FALSE){

  #Checks
  x <- hash_checks(x,salt)

  #Call and return
  .Call(R_digest, as.character(x), as.character(algo))
}

#' @rdname hash
#' @export
rawhash <- function(x, algo){
  .Call(R_digest_raw, as.character(x), as.character(algo))
}

hash_checks <- function(x,salt){

  #Check type, presence of NA values
  if(any(is.list(x),is.data.frame(x))){
    warning("x must be a vector. Attempting to convert.")
    x <- unlist(x)
  }
  if(any(is.na(x))){
    warning("x contains NA values (possibly from conversion).")
  }

  #Is a random value desired?
  if(salt){
    x <- paste0(x,rand_bytes(1))
  }

  #Return
  return(x)
}
