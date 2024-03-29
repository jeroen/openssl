#' OpenSSH fingerprint
#'
#' Calculates the OpenSSH fingerprint of a public key. This value should
#' match what you get to see when connecting with SSH to a server. Note
#' that some other systems might use a different algorithm to derive a
#' (different) fingerprint for the same keypair.
#'
#' @export
#' @param key a public or private key
#' @param hashfun which hash function to use to calculate the fingerprint
#' @examples mykey <- rsa_keygen()
#' pubkey <- as.list(mykey)$pubkey
#' fingerprint(mykey)
#' fingerprint(pubkey)
#'
#' # Some systems use other hash functions
#' fingerprint(pubkey, sha1)
#' fingerprint(pubkey, sha256)
#'
#' # Other key types
#' fingerprint(dsa_keygen())
fingerprint <- function(key, hashfun = sha256){
  UseMethod("fingerprint")
}

#' @export
fingerprint.key <- function(key, hashfun = sha256){
  pubkey <- derive_pubkey(key)
  fingerprint(pubkey, hashfun = hashfun)
}

#' @export
fingerprint.pubkey <- function(key, hashfun = sha256){
  hashdata <- fpdata(key)
  hashfun(unlist(unname(hashdata)))
}

fpdata <- function(pubkey){
  UseMethod("fpdata")
}

fpdata.rsa <- function(pubkey){
  input <- c(list(charToRaw("ssh-rsa")), decompose(pubkey))
  lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
}

fpdata.dsa <- function(pubkey){
  input <- c(list(charToRaw("ssh-dss")), decompose(pubkey))
  lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
}

fpdata.ecdsa <- function(pubkey){
  bindata <- decompose(pubkey)
  nist_name <- bindata[[1]]
  ssh_name <- switch(nist_name,
    "P-256" = "nistp256",
    "P-384" = "nistp384",
    "P-521" = "nistp521",
    stop("Unknown curve type: ", nist_name)
  )
  keydata <- c(as.raw(4), bindata[[2]], bindata[[3]])
  input <- c(list(charToRaw(paste0("ecdsa-sha2-", ssh_name))), list(charToRaw(ssh_name)), list(keydata))
  lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
}

fpdata.x25519 <- function(pubkey){
  buf <- write_raw_pubkey(pubkey)
  input <- c(list(charToRaw("ssh-x25519")), list(buf))
  lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
}

fpdata.ed25519 <- function(pubkey){
  buf <- write_raw_pubkey(pubkey)
  input <- c(list(charToRaw("ssh-ed25519")), list(buf))
  lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
}

#' @useDynLib openssl R_pubkey_type
pubkey_type <- function(key){
  .Call(R_pubkey_type, key)
}

#' @useDynLib openssl R_pubkey_bitsize
pubkey_bitsize <- function(key){
  .Call(R_pubkey_bitsize, key)
}

decompose <- function(x, ...){
  UseMethod("decompose")
}

decompose.pubkey <- function(x, ...){
  UseMethod("pubkey_decompose")
}

decompose.key <- function(x, ...){
  UseMethod("priv_decompose")
}

#' @useDynLib openssl R_rsa_pubkey_decompose
pubkey_decompose.rsa <- function(key){
  out <- .Call(R_rsa_pubkey_decompose, key)
  structure(out, names = c("e", "n"))
}

#' @useDynLib openssl R_rsa_priv_decompose
priv_decompose.rsa <- function(key){
  out <- .Call(R_rsa_priv_decompose, key)
  structure(out, names = c("e", "n", "p", "q", "d", "dp", "dq", "qi"))
}

#' @useDynLib openssl R_dsa_pubkey_decompose
pubkey_decompose.dsa <- function(key){
  out <- .Call(R_dsa_pubkey_decompose, key)
  structure(out, names = c("p", "q", "g", "y"))
}

#' @useDynLib openssl R_dsa_priv_decompose
priv_decompose.dsa <- function(key){
  out <- .Call(R_dsa_priv_decompose, key)
  structure(out, names = c("p", "q", "g", "y", "x"))
}

#' @useDynLib openssl R_ecdsa_pubkey_decompose
pubkey_decompose.ecdsa <- function(key){
  out <- .Call(R_ecdsa_pubkey_decompose, key)
  structure(out, names = c("curve", "x", "y"))
}

#' @useDynLib openssl R_ecdsa_priv_decompose
priv_decompose.ecdsa <- function(key){
  out <- .Call(R_ecdsa_priv_decompose, key)
  structure(out, names = c("curve", "x", "y", "secret"))
}

pubkey_decompose.x25519 <- pubkey_decompose.ed25519 <- function(x){
  write_raw_pubkey(x)
}

priv_decompose.ed25519 <- priv_decompose.x25519 <- function(x){
  write_raw_key(x)
}

privdata <- function(x, ...){
  UseMethod("priv_keydata")
}

priv_keydata.rsa <- function(key){
  privdata <- decompose(key)
  c('ssh-rsa', privdata[c("n", "e", "d", "qi", "p", "q")])
}

priv_keydata.dsa <- function(key){
  data <- decompose(key)
  c('ssh-dss', data[c("p", "q", "g", "y", "x")])
}

priv_keydata.ecdsa <- function(key){
  privdata <- decompose(key)
  curve <- switch(privdata$curve,
     "P-256" = "nistp256",
     "P-384" = "nistp384",
     "P-521" = "nistp521",
     stop("Unknown curve type: ", privdata$curve)
  )
  list(paste0("ecdsa-sha2-", curve), curve, c(as.raw(4), privdata$x, privdata$y), privdata$secret)
}

priv_keydata.ed25519 <- function(key){
  pubdata <- decompose(key$pubkey)
  privdata <- decompose(key)
  list("ssh-ed25519", pubdata, c(privdata, pubdata))
}
