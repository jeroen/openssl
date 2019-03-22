#' @useDynLib openssl R_dsa_pubkey_build
dsa_pubkey_build <- function(p, q, g, y){
  .Call(R_dsa_pubkey_build, p, q, g, y)
}

#' @useDynLib openssl R_dsa_key_build
dsa_key_build <- function(p, q, g, y, x){
  .Call(R_dsa_key_build, p, q, g, y, x)
}

#' @useDynLib openssl R_rsa_pubkey_build
rsa_pubkey_build <- function(exp, mod){
  .Call(R_rsa_pubkey_build, exp, mod)
}

#' @useDynLib openssl R_rsa_key_build
rsa_key_build <- function(e, n, p, q, d, qi = bignum_mod_inv(q, p), dp = (d %% (p-1)), dq = (d %% (q-1))){
  .Call(R_rsa_key_build, n, e, d, qi, p, q, dp, dq)
}

#' @useDynLib openssl R_ecdsa_pubkey_build
ecdsa_pubkey_build <- function(x, y, nist_name){
  .Call(R_ecdsa_pubkey_build, x, y, nist_name);
}

#' @useDynLib openssl R_ecdsa_key_build
ecdsa_key_build <- function(x, y, secret, nist_name){
  .Call(R_ecdsa_key_build, x, y, secret, nist_name)
}
