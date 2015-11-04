fingerprint <- function(x, ...){
  UseMethod("fingerprint")
}

fingerprint.rsa <- function(pubkey){
  input <- c(list(charToRaw("ssh-rsa")), rsa_decompose(pubkey))
  out <- lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
  md5(unlist(unname(out)))
}

fingerprint.dsa <- function(pubkey){
  input <- c(list(charToRaw("ssh-dss")), dsa_decompose(pubkey))
  out <- lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
  md5(unlist(unname(out)))
}

fingerprint.ecdsa <- function(pubkey){
  bn <- ecdsa_decompose(pubkey)
  keydata <- c(as.raw(4), bn[[1]], bn[[2]])
  input <- c(list(charToRaw("ecdsa-sha2-nistp256")), list(charToRaw("nistp256")), list(keydata))
  out <- lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
  md5(unlist(unname(out)))
}

fingerprint.ed25519 <- function(pubkey){
  input <- c(list(charToRaw("ssh-ed25519")), list(pubkey))
  out <- lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
  md5(unlist(unname(out)))
}

#' @useDynLib openssl R_pubkey_type
pubkey_type <- function(key){
  .Call(R_pubkey_type, key)
}

#' @useDynLib openssl R_rsa_decompose
rsa_decompose <- function(key){
  .Call(R_rsa_decompose, key)
}

#' @useDynLib openssl R_dsa_decompose
dsa_decompose <- function(key){
  .Call(R_dsa_decompose, key)
}

#' @useDynLib openssl R_ecdsa_decompose
ecdsa_decompose <- function(key){
  .Call(R_ecdsa_decompose, key)
}
