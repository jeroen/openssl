#' Encrypt for Travis
#'
#' Travis-CI allows for including small pieces of encrypted data with the
#' configuration file such as passwords or access tokens.
#'
#' Travis generates a unique RSA keypair for each repository and publishes
#' the public key via an API. We can use this to encrypt small pieces of
#' secret data (such as passwords or tokens) in a way that only the Travis
#' servers can decipher.
#'
#' @export
#' @rdname travis_encrypt
#' @references \url{http://docs.travis-ci.com/user/encryption-keys/}
#' @param repo travis repository in "user/repo" format (similar to
#' \link[devtools:install_github]{install_github})
travis_pubkey <- function(repo){
  url <- sprintf("https://api.travis-ci.org/repos/%s/key", repo)
  keystr <- gsub("RSA PUBLIC", "PUBLIC", jsonlite::fromJSON(url)$key)
  read_pubkey(textConnection(keystr))
}

#' @export
#' @rdname travis_encrypt
#' @param data raw or character vector to encrypt
#' @param pubkey a key returned by \code{\link{travis_pubkey}}, or a \code{repo}
#' to be passed to \code{\link{travis_pubkey}}
#' @examples # Encrypt environment variable
#' pubkey <- travis_pubkey("jeroenooms/jsonlite")
#' travis_encrypt("TOKEN=12345", pubkey)
#' travis_encrypt("TOKEN=12345", "jeroenooms/jsonlite")
travis_encrypt <- function(data, pubkey){
  if(is.character(data)){
    data <- charToRaw(paste(data, collapse = "\n"))
  }
  if(is.character(pubkey))
    pubkey <- travis_pubkey(pubkey)
  buf <- rsa_encrypt(data, pubkey)
  str <- sprintf(' - secure: "%s"\n', openssl::base64_encode(buf))
  cat(str)
  invisible(str)
}
