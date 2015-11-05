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
  bindata <- ecdsa_decompose(pubkey)
  nist_name <- bindata[[1]]
  key_bits <- switch(nist_name,
    "P-256" = 256,
    "P-384" = 384,
    "P-521" = 521,
    stop("Unknown curve type: ", nist_name)
  )
  key_size <- ceiling(key_bits/8)
  ssh_name <- paste0("nistp", key_bits)
  keydata <- c(as.raw(4), pad(bindata[[2]], key_size), pad(bindata[[3]], key_size))
  input <- c(list(charToRaw(paste0("ecdsa-sha2-", ssh_name))), list(charToRaw(ssh_name)), list(keydata))
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

# SSH integer blogs need fixed size but openssl drops leading zero's
pad <- function(x, size){
  dif <- size - length(x)
  c(raw(dif), x)
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
