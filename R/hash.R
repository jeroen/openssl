#' Vectorized hash/hmac functions
#'
#' All hash functions either calculate a hash-digest for \code{key == NULL} or HMAC
#' (hashed message authentication code) when \code{key} is not \code{NULL}. Supported
#' inputs are binary (raw vector), strings (character vector) or a connection object.
#'
#' Functions are vectorized for the case of character vectors: a vector with \code{n}
#' strings returns \code{n} hashes. When passing a connection object, the contents will
#' be stream-hashed which minimizes the amount of required memory. This is recommended
#' for hashing files from disk or network.
#'
#' The sha2 family of algorithms (sha224, sha256, sha384 and sha512) is generally
#' recommended for sensitive information. While sha1 and md5 are usually sufficient for
#' collision-resistant identifiers, they are no longer considered secure for cryptographic
#' purposes.
#'
#' In applications where hashes should be irreversible (such as names or passwords) it is
#' often recommended to use a random \emph{key} for HMAC hashing. This prevents attacks where
#' we can lookup hashes of common and/or short strings. See examples. A common special case
#' is adding a random salt to a large number of records to test for uniqueness within the
#' dataset, while simultaneously rendering the results incomparable to other datasets.
#'
#' @param x character vector, raw vector or connection object.
#' @param key string or raw vector used as the key for HMAC hashing
#' @param size must be equal to 224 256 384 or 512
#' @references OpenSSL manual: \url{https://www.openssl.org/docs/crypto/EVP_DigestInit.html}.
#' Digest types: \url{https://www.openssl.org/docs/apps/dgst.html}
#' @export
#' @aliases hmac mac
#' @rdname hash
#' @name hashing
#' @useDynLib openssl R_digest_raw R_digest
#' @examples # Support both strings and binary
#' md5(c("foo", "bar"))
#' md5(charToRaw("foo"))
#' md5("foo", key = "secret")
#'
#' # Compare to digest
#' digest::digest("foo", "md5", serialize = FALSE)
#'
#' # Other way around
#' digest::digest(cars, skip = 0)
#' md5(serialize(cars, NULL))
#'
#' # Stream-verify from connections (including files)
#' myfile <- system.file("CITATION")
#' md5(file(myfile))
#' md5(file(myfile), key = "secret")
#'
#' \dontrun{check md5 from: http://cran.r-project.org/bin/windows/base/old/3.1.1/md5sum.txt
#' md5(url("http://cran.r-project.org/bin/windows/base/old/3.1.1/R-3.1.1-win.exe"))}
#'
#' # Use a salt to prevent dictionary attacks
#' sha1("admin") # googleable
#' sha1("admin", key = "random_salt_value") #not googleable
#'
#' # Use a random salt to identify duplicates while anonymizing values
#' sha256("john") # googleable
#' sha256(c("john", "mary", "john"), key = "random_salt_value")
sha1 <- function(x, key = NULL){
  rawstringhash(x, "sha1", key)
}

#' @rdname hash
#' @export
sha224 <- function(x, key = NULL){
  rawstringhash(x, "sha224", key)
}

#' @rdname hash
#' @export
sha256 <- function(x, key = NULL){
  rawstringhash(x, "sha256", key)
}

#' @rdname hash
#' @export
sha384 <- function(x, key = NULL){
  rawstringhash(x, "sha384", key)
}

#' @rdname hash
#' @export
sha512 <- function(x, key = NULL){
  rawstringhash(x, "sha512", key)
}

#' @rdname hash
#' @export
sha2 <- function(x, size = 256, key = NULL){
  rawstringhash(x, paste0("sha", size), key)
}

#' @rdname hash
#' @export
md4 <- function(x, key = NULL){
  rawstringhash(x, "md4", key)
}

#' @rdname hash
#' @export
md5 <- function(x, key = NULL){
  rawstringhash(x, "md5", key)
}

#' @rdname hash
#' @export
ripemd160 <- function(x, key = NULL){
  rawstringhash(x, "ripemd160", key)
}

# Low level interfaces, not exported.
rawhash <- function(x, algo, key = NULL){
  stopifnot(is.raw(x))
  stopifnot(is.null(key) || is.raw(key))
  .Call(R_digest_raw, x, as.character(algo), key)
}

#' @useDynLib openssl R_digest
stringhash <- function(x, algo, key = NULL){
  stopifnot(is.character(x))
  stopifnot(is.null(key) || is.raw(key))
  .Call(R_digest,x, as.character(algo), key)
}

connectionhash <- function(con, algo){
  md <- md_init(algo);
  if(!isOpen(con)){
    open(con, "rb")
    on.exit(close(con))
  }
  if(summary(con)$text == "binary"){
    while(length(data <- readBin(con, raw(), 512*1024))){
      md_feed(md, data)
    }
  } else {
    while(length(data <- readLines(con, n = 1L, warn = FALSE))){
      md_feed(md, charToRaw(data))
    }
  }
  md_final(md)
}

connectionhmac <- function(con, algo, key){
  if(is.character(key))
    key <- charToRaw(key)
  hmac <- hmac_init(algo, key);
  if(!isOpen(con)){
    open(con, "rb")
    on.exit(close(con))
  }
  if(summary(con)$text == "binary"){
    while(length(data <- readBin(con, raw(), 1024))){
      hmac_feed(hmac, data)
    }
  } else {
    while(length(data <- readLines(con, n = 1L, warn = FALSE))){
      hmac_feed(hmac, charToRaw(data))
    }
  }
  hmac_final(hmac)
}

rawstringhash <- function(x, algo, key){
  if(is.character(key))
    key <- charToRaw(key)
  hash <- if(inherits(x, "connection")){
    if(is.null(key)){
      connectionhash(x, algo)
    } else {
      connectionhmac(x, algo, key)
    }
  } else if(is.raw(x)){
    rawhash(x, algo, key)
  } else if(is.character(x)){
    stringhash(x, algo, key)
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
