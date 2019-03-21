#' Bcrypt PWKDF
#'
#' Password based key derivation function with bcrypt.
#'
#' @export
#' @rdname pbkdf
#' @useDynLib openssl R_bcrypt_pbkdf
#' @param password string or raw vector with password
#' @param salt raw vector with (usually 16) bytes
#' @param rounds number of hashing rounds
#' @param size desired length of the output key
bcrypt_pbkdf <- function(password, salt, rounds = 16L, size = 32L){
  if(is.character(password))
    password <- charToRaw(password)
  stopifnot(is.raw(password))
  stopifnot(is.raw(salt))
  stopifnot(is.integer(rounds))
  stopifnot(is.integer(size))
  .Call(R_bcrypt_pbkdf, password, salt, rounds, size)
}
