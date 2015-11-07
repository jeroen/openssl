fingerprint <- function(x, hashfun = md5, ...){
  hashdata <- fpdata(x)
  hashfun(unlist(unname(hashdata)))
}

fpdata <- function(x, ...){
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

fpdata.ed25519 <- function(pubkey){
  input <- c(list(charToRaw("ssh-ed25519")), list(pubkey))
  lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
}

#' @useDynLib openssl R_pubkey_type
pubkey_type <- function(key){
  .Call(R_pubkey_type, key)
}

decompose <- function(x, ...){
  UseMethod("decompose")
}

#' @useDynLib openssl R_rsa_decompose
decompose.rsa <- function(key){
  out <- .Call(R_rsa_decompose, key)
  structure(out, names = c("e", "n"))
}

#' @useDynLib openssl R_dsa_decompose
decompose.dsa <- function(key){
  out <- .Call(R_dsa_decompose, key)
  structure(out, names = c("p", "q", "g", "h"))
}

#' @useDynLib openssl R_ecdsa_decompose
decompose.ecdsa <- function(key){
  out <- .Call(R_ecdsa_decompose, key)
  structure(out, names = c("curve", "x", "y"))
}

decompose.ed25519 <- function(key){
  unclass(key)
}
