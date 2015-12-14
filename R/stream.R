#' @useDynLib openssl R_md_init
md_init <- function(algo){
  .Call(R_md_init, as.character(algo))
}

#' @useDynLib openssl R_md_feed
md_feed <- function(md, data){
  stopifnot(inherits(md, "md"))
  stopifnot(is.raw(data))
  .Call(R_md_feed, md, data)
}

#' @useDynLib openssl R_md_final
md_final <- function(md){
  stopifnot(inherits(md, "md"))
  .Call(R_md_final, md)
}

#' @useDynLib openssl R_hmac_init
hmac_init <- function(algo, key){
  .Call(R_hmac_init, as.character(algo), key)
}

#' @useDynLib openssl R_hmac_feed
hmac_feed <- function(ptr, data){
  stopifnot(inherits(ptr, "md"))
  stopifnot(is.raw(data))
  .Call(R_hmac_feed, ptr, data)
}

#' @useDynLib openssl R_hmac_final
hmac_final <- function(md){
  stopifnot(inherits(md, "md"))
  .Call(R_hmac_final, md)
}

