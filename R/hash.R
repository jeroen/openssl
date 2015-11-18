#' Vectorized hashing functions
#'
#' Bindings to hash functions in OpenSSL. Supported inputs are binary (raw vector),
#' strings (character vector) or a connection object. Functions are vectorized for
#' the case of character vectors: a vector with \code{n} strings returns \code{n}
#' hashes. When passing a connection object, the contents will be stream-hashed which
#' minimizes the amount of required memory.
#'
#' The "sha256" algorithm is generally recommended for sensitive information. While md5
#' and weaker members of the sha family are usually sufficient for collision-resistant
#' identifiers, they are no longer considered secure for cryptographic purposes.
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
#' @name hashing
#' @useDynLib openssl R_digest_raw R_digest
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
#' sha256(c("john", "mary", "john"), salt = "some_random_salt_value")
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

#' @useDynLib openssl R_digest
stringhash <- function(x, algo, salt = ""){
  # Must be character vector
  stopifnot(is.character(x))
  if(is.raw(salt)){
    salt <- rawToChar(salt)
  }
  if(nchar(salt)){
    x <- paste0(x, salt)
  }
  .Call(R_digest,x, as.character(algo))
}

connectionhash <- function(con, algo, salt){
  md <- md_init(algo);
  if(!isOpen(con)){
    open(con, "rb")
    on.exit(close(con))
  }
  if(is.character(salt)){
    salt <- charToRaw(salt);
  }
  stopifnot(is.raw(salt))
  md_feed(md, salt)
  while(length(data <- readBin(con, raw(), 512*1024))){
    md_feed(md, data)
  }
  md_final(md)
}

rawstringhash <- function(x, algo, salt){
  hash <- if(inherits(x, "connection")){
    connectionhash(x, algo, salt)
  } else if(is.raw(x)){
    rawhash(x, algo, salt)
  } else if(is.character(x)){
    stringhash(x, algo, salt)
  } else {
    stop("Argument 'x' must be raw or character vector.")
  }
  structure(hash, class = c("hash", algo))
}

hash_type <- function(hash){
  if(!is.raw(hash))
    stop("hash must be raw vector or hex string")
  if(inherits(hash, "md5") || length(hash) == 16){
    "md5"
  } else if(inherits(hash, "sha1") || length(hash) == 20){
    "sha1"
  } else if(inherits(hash, "sha256") || length(hash) == 32){
    "sha256"
  } else{
    stop("Hash of length ", length(hash), " not supported")
  }
}

is_hexraw <- function(str){
  is.character(str) &&
  (length(str) == 1) &&
  grepl("^[a-f0-9 :]+$", tolower(str))
}

hex_to_raw <- function(str){
  stopifnot(length(str) == 1)
  str <- gsub("[ :]", "", str)
  len <- nchar(str)/2
  out <- raw(len)
  for(i in 1:len){
    out[i] <- as.raw(as.hexmode(substr(str, 2*i-1, 2*i)))
  }
  out
}

parse_hash <- function(x){
  if(is.raw(x)) return(x)
  if(is.character(x)) return(hex_to_raw(x[1]))
  stop("Invalid hash: ", x)
}

#' @export
print.hash <- function(x, ...){
  if(is.raw(x))
    cat(class(x)[2], paste(x, collapse = ":"), "\n")
  else
    print(unclass(x, ...))
}
