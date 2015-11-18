#' Encode and decode base64
#'
#' Encode and decode binary data into a base64 string. Character vectors are
#' automatically collapsed into a single string.
#'
#' @rdname base64_encode
#' @useDynLib openssl R_base64_encode
#' @param bin raw or character vector with data to encode into base64
#' @param linebreaks insert linebreaks in the base64 message to make it more readable
#' @param text string with base64 data to decode
#' @export
#' @examples input <- charToRaw("foo = bar + 5")
#' message <- base64_encode(input)
#' output <- base64_decode(message)
#' identical(output, input)
base64_encode <- function(bin, linebreaks = FALSE){
  if(is.character(bin)){
    bin <- charToRaw(paste(bin, collapse=""))
  }
  stopifnot(is.raw(bin))
  .Call(R_base64_encode, bin, as.logical(linebreaks))
}

#' @rdname base64_encode
#' @useDynLib openssl R_base64_decode
#' @export
base64_decode <- function(text){
  if(is.raw(text)){
    text <- rawToChar(text)
  }
  stopifnot(is.character(text))
  text <- paste(text, collapse="")
  text <- gsub("[\r\n]", "", text)[[1]]
  .Call(R_base64_decode, text)
}
