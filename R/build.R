#' @useDynLib openssl R_ecdsa_pubkey_build
ecdsa_pubkey_build <- function(x, y, nist_name){
  .Call(R_ecdsa_pubkey_build, x, y, nist_name);
}

#' @useDynLib openssl R_dsa_pubkey_build
dsa_pubkey_build <- function(p,q,g,y){
  .Call(R_dsa_pubkey_build, p, q, g, y)
}

#' @useDynLib openssl R_rsa_pubkey_build
rsa_pubkey_build <- function(exp, mod){
  .Call(R_rsa_pubkey_build, exp, mod)
}
