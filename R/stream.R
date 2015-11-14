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
