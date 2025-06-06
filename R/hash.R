#' Vectorized hash/hmac functions
#'
#' All hash functions either calculate a hash-digest for `key == NULL` or HMAC
#' (hashed message authentication code) when `key` is not `NULL`. Supported
#' inputs are binary (raw vector), strings (character vector) or a connection object.
#'
#' The most efficient way to calculate hashes is by using input [connections],
#' such as a [file()][base::connections] or [url()][base::connections] object.
#' In this case the hash is calculated streamingly, using almost no memory or disk space,
#' regardless of the data size. When using a connection input in the [multihash]
#' function, the data is only read only once while streaming to multiple hash functions
#' simultaneously. Therefore several hashes are calculated simultanously, without the
#' need to store any data or download it multiple times.
#'
#' Functions are vectorized for the case of character vectors: a vector with `n`
#' strings returns `n` hashes. When passing a connection object, the contents will
#' be stream-hashed which minimizes the amount of required memory. This is recommended
#' for hashing files from disk or network.
#'
#' The sha2 family of algorithms (sha224, sha256, sha384 and sha512) is generally
#' recommended for sensitive information. While sha1 and md5 are usually sufficient for
#' collision-resistant identifiers, they are no longer considered secure for cryptographic
#' purposes.
#'
#' In applications where hashes should be irreversible (such as names or passwords) it is
#' often recommended to use a random *key* for HMAC hashing. This prevents attacks where
#' we can lookup hashes of common and/or short strings. See examples. A common special case
#' is adding a random salt to a large number of records to test for uniqueness within the
#' dataset, while simultaneously rendering the results incomparable to other datasets.
#'
#' The `blake2b` and `blake2s` algorithms are only available if your system has
#' libssl 1.1 or newer.
#'
#' NB R base `file()` function has a poor default `raw = FALSE` which causes files to get
#' altereted (e.g. decompressed) when reading. Use `file(path, raw = TRUE)` to get the
#' hash of the file as it exists on your disk.
#'
#' @param x character vector, raw vector or connection object.
#' @param key string or raw vector used as the key for HMAC hashing
#' @param size must be equal to 224 256 384 or 512
#' @references Digest types: <https://docs.openssl.org/1.1.1/man1/dgst/>
#' @export
#' @aliases hash hmac mac
#' @rdname hash
#' @name hashing
#' @useDynLib openssl R_digest_raw R_digest
#' @examples # Support both strings and binary
#' md5(c("foo", "bar"))
#' md5("foo", key = "secret")
#'
#' hash <- md5(charToRaw("foo"))
#' as.character(hash, sep = ":")
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
#' md5(file(myfile, raw = TRUE))
#' md5(file(myfile, raw = TRUE), key = "secret")
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
keccak <- function(x, size = 256, key = NULL){
  # Keccak is not available on OpenSSL < 3.2 or LibreSSL
  rawstringhash(x, paste0("keccak-", size), key)
}

#' @rdname hash
#' @export
sha2 <- function(x, size = 256, key = NULL){
  rawstringhash(x, paste0("sha", size), key)
}

#' @rdname hash
#' @export
sha3 <- function(x, size = 256, key = NULL){
  rawstringhash(x, paste0("sha3-", size), key)
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
blake2b <- function(x, key = NULL){
  rawstringhash(x, "blake2b512", key)
}

#' @rdname hash
#' @export
blake2s <- function(x, key = NULL){
  rawstringhash(x, "blake2s256", key)
}

#' @rdname hash
#' @export
ripemd160 <- function(x, key = NULL){
  rawstringhash(x, "ripemd160", key)
}

#' @rdname hash
#' @export
#' @param algos string vector with names of hashing algorithms
multihash <- function(x, algos = c('md5', 'sha1', 'sha256', 'sha384', 'sha512')){
  if(inherits(x, 'connection')){
    connectionhashes(x, algos = algos)
  } else if(is.raw(x)){
    out <- lapply(algos, function(algo){rawstringhash(x, algo = algo, key = NULL)})
    structure(out, names = algos)
  } else if(is.character(x)){
    m <- vapply(algos, function(algo){stringhash(x, algo = algo, key = NULL)}, FUN.VALUE = x)
    if(length(x) == 1)
      m <- t(m)
    data.frame(m, stringsAsFactors = FALSE)
  }
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

connectionhashes <- function(con, algos){
  if(!isOpen(con)){
    open(con, "rb")
    on.exit(close(con))
  }
  mds <- lapply(algos, function(algo){
    structure(md_init(algo), algo = algo)
  })
  if(summary(con)$text == "binary"){
    while(length(data <- readBin(con, raw(), 512*1024))){
      lapply(mds, md_feed, data = data)
    }
  } else {
    while(length(data <- readLines(con, n = 1L, warn = FALSE))){
      lapply(mds, md_feed, data = charToRaw(data))
    }
  }
  hashes <- lapply(mds, function(md){
    structure(md_final(md), class = c("hash", attr(md, 'algo')))
  })
  structure(hashes, names = algos)
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
      connectionhashes(x, algo)[[algo]]
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
  out <- structure(hash, class = c("hash", algo))
  if(!is.null(key))
    class(out) <- c(class(out), "hmac")
  out
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
print.hash <- function(x, sep = ":", ...){
  if(is.raw(x))
    cat(class(x)[-1], as.character(x, sep = sep), "\n")
  else
    print(unclass(x, ...))
}

#' @export
as.character.hash <- function(x, sep = "", ...){
  if(is.raw(x))
    structure(paste(unclass(x), collapse = sep), class = class(x))
  else if(is.character(x))
    unclass(x)
  else x
}
