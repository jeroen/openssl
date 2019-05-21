#' @useDynLib openssl R_read_raw_key_ed25519
read_raw_key_ed25519 <- function(x){
  .Call(R_read_raw_key_ed25519, x)
}

#' @useDynLib openssl R_read_raw_pubkey_ed25519
read_raw_pubkey_ed25519 <- function(x){
  .Call(R_read_raw_pubkey_ed25519, x)
}

#' @useDynLib openssl R_read_raw_key_x25519
read_raw_key_x25519 <- function(x){
  .Call(R_read_raw_key_x25519, x)
}

#' @useDynLib openssl R_read_raw_pubkey_x25519
read_raw_pubkey_x25519 <- function(x){
  .Call(R_read_raw_pubkey_x25519, x)
}

#' @useDynLib openssl R_write_raw_key
write_raw_key <- function(x){
  .Call(R_write_raw_key, x)
}

#' @useDynLib openssl R_write_raw_pubkey
write_raw_pubkey <- function(x){
  .Call(R_write_raw_pubkey, x)
}

#' @useDynLib openssl R_data_sign
data_sign <- function(data, key){
  .Call(R_data_sign, data, key)
}

#' @useDynLib openssl R_data_verify
data_verify <- function(data, sig, pubkey){
  .Call(R_data_verify, data, sig, pubkey)
}
