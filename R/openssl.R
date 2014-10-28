# Generate random bytes with OpenSSL
#
# These functions interface to the OpenSSL random number generators. They
# can generate crypto secure random numbers in R.
#
#' @title Generate random bytes with OpenSSL
#' @rdname rand_bytes
#' @useDynLib openssl R_RAND_bytes
#' @param n number of random bytes to generate
#' @export
#' @references OpenSSL manual: \url{https://www.openssl.org/docs/crypto/RAND_bytes.html}
#' @examples rnd <- rand_bytes(10)
#' as.numeric(rnd)
#' as.character(rnd)
#' as.logical(rawToBits(rnd))
#'
#' # numbers range from 0 to 255
#' rnd <- rand_bytes(100000)
#' hist(as.numeric(rnd), breaks=-1:255)
#'
#' # Generate random doubles between 0 and 1
#' rand_num(5)
rand_bytes <- function(n = 1){
  .Call(R_RAND_bytes, n, FALSE)
}

#' @rdname rand_bytes
#' @export
rand_pseudo_bytes <- function(n = 1){
  .Call(R_RAND_bytes, n, TRUE)
}
