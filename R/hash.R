#' Vectorized hashing functions
#'
#' Bindings to cryptographic hashing functions available in OpenSSL's libcrypto. Both
#' binary and string inputs are supported and the output type will match the input type.
#' Functions are fully vectorized for the case of character vectors: a vector with
#' \code{n} strings will return \code{n} hashes.
#'
#' The family of hashing functions implement bindings to OpenSSL's crypto module, which
#' allow for cryptographically hashing strings and raw (binary) vectors. When passing
#' a connection object, they will stream-hash binary contents. To hash other types of
#' objects, use a suitable mapping function such as \code{\link{serialize}} or
#' \code{\link{as.character}}.
#'
#' The full range of OpenSSL-supported cryptographic functions are available. The "sha256"
#' or "sha512" algorithm is generally recommended for sensitive information. While md5 and
#' weaker members of the sha family are probably sufficient for collision-resistant identifiers,
#' cryptographic weaknesses have been directly or indirectly identified in their output.
#'
#' In applications where hashes should be irreversible (such as names or passwords) it is
#' often recommended to add a random, fixed \emph{salt} to each input before hashing. This
#' prevents attacks where we can lookup hashes of common and/or short strings. See examples.
#' An common special case is adding a random salt to a large number of records to test for
#' uniqueness within the dataset, while simultaneously rendering the results incomparable
#' to other datasets.
#'
#' @param x a character, raw vector or connection object.
#' @param salt a \href{http://en.wikipedia.org/wiki/Salt_(cryptography)}{salt}
#' appended to each input element to anonymize or prevent dictionary attacks. See details.
#' @references OpenSSL manual: \url{https://www.openssl.org/docs/crypto/EVP_DigestInit.html}.
#' Digest types: \url{https://www.openssl.org/docs/apps/dgst.html}
#' @export
#' @rdname hash
#' @name crypto digest
#' @useDynLib openssl R_digest_raw R_digest R_openssl_init R_openssl_cleanup
#' @examples # Support both strings and binary
#' md5("foo")
#' md5(charToRaw("foo"))
#'
#' # Compare to digest
#' library(digest)
#' digest("foo", "md5", serialize = FALSE)
#'
#' # Other way around
#' digest(cars, skip = 0)
#' md5(serialize(cars, NULL))
#'
#' # Vectorized for strings
#' md5(c("foo", "bar", "baz"))
#'
#' # Stream-verify from connections (including files)
#' myfile <- system.file("CITATION")
#' md5(file(myfile))
#'
#' \dontrun{check md5 from: http://cran.r-project.org/bin/windows/base/old/3.1.1/md5sum.txt
#' md5(url("http://cran.r-project.org/bin/windows/base/old/3.1.1/R-3.1.1-win.exe"))}
#'
#' # Use a salt to prevent dictionary attacks
#' sha1("admin") # googleable
#' sha1("admin", salt="some_random_salt_value") #not googleable
#'
#' # Use a random salt to identify duplicates while anonymizing values
#' sha256("john") # googleable
#' sha256(c("john", "mary", "john"), salt = rand_bytes(100))
sha1 <- function(x, salt = ""){
  rawstringhash(x, "sha1", salt)
}

#' @rdname hash
#' @export
sha256 <- function(x, salt = ""){
  rawstringhash(x, "sha256", salt)
}

#' @rdname hash
#' @export
sha512 <- function(x, salt = ""){
  rawstringhash(x, "sha512", salt)
}

#' @rdname hash
#' @export
md4 <- function(x, salt = ""){
  rawstringhash(x, "md4", salt)
}

#' @rdname hash
#' @export
md5 <- function(x, salt = ""){
  rawstringhash(x, "md5", salt)
}

#' @rdname hash
#' @export
ripemd160 <- function(x, salt = ""){
  rawstringhash(x, "ripemd160", salt)
}

# Low level interfaces, not exported.
rawhash <- function(x, algo, salt = raw()){
  stopifnot(is.raw(x))
  if(is.character(salt)){
    salt <- charToRaw(salt)
  }
  stopifnot(is.raw(salt))
  if(length(salt)){
    x <- c(x, salt)
  }
  .Call(R_digest_raw, x, as.character(algo))
}

stringhash <- function(x, algo, salt = ""){
  # Must be character vector
  stopifnot(is.character(x))
  if(nchar(salt)){
    x <- paste0(salt, collapse="")
  }
  .Call(R_digest,x, as.character(algo))
}

connectionhash <- function(con, algo, salt){
  md <- md_init(algo);
  open(con, "rb")
  on.exit(close(con))
  if(is.character(salt)){
    salt <- charToRaw(salt);
  }
  stopifnot(is.raw(salt))
  md_feed(md, salt)
  cat("Hashing...")
  while(length(data <- readBin(con, raw(), 512*1024))){
    md_feed(md, data)
    cat(".")
  }
  cat("\n")
  md_final(md)
}

rawstringhash <- function(x, algo, salt){
  if(is(x, "connection")){
    connectionhash(x, algo, salt)
  } else if(is.raw(x)){
    rawhash(x, algo, salt)
  } else if(is.character(x)){
    stringhash(x, algo, salt)
  } else {
    stop("Argument 'x' must be raw or character vector.")
  }
}
