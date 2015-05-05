#' Encode and decode base64
#'
#' Encode and decode binary data into a base64 string. Character vectors are
#' automatically collapse into a single string.
#'
#' @rdname base64
#' @useDynLib openssl R_base64_encode
#' @param bin Data to encode. Must be raw or character vector.
#' @param text The base64 message to decode. Must be a string.
#' @export
#' @examples input <- charToRaw("foo = bar + 5")
#' message <- base64_encode(input)
#' output <- base64_decode(message)
#' identical(output, input)
base64_encode <- function(bin){
  if(is.character(bin)){
    bin <- charToRaw(paste(bin, collapse=""))
  }
  stopifnot(is.raw(bin))
  .Call(R_base64_encode, bin)
}

#' @rdname base64
#' @useDynLib openssl R_base64_decode
#' @export
base64_decode <- function(text){
  if(is.raw(text)){
    text <- rawToChar(text)
  }
  stopifnot(is.character(text))
  .Call(R_base64_decode, paste(text, collapse=""))
}
