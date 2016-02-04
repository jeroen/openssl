#' Encode and decode base64
#'
#' Encode and decode binary data into a base64 string. Character vectors are
#' automatically collapsed into a single string.
#'
#' The \code{base64url_encode} functions are specified in Section 5 of RFC 4648
#' as a URL-safe alternative to the standard base64. They use different characters
#' for the 62:nd and 63:rd alphabet character and don't include trailing \code{==}
#' padding.
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

# defined by rfc7515, rfc7519
#' @rdname base64_encode
#' @export
base64url_encode <- function(bin){
  text <- base64_encode(bin)
  sub("=+$", "", chartr('+/', '-_', text))
}

#' @rdname base64_encode
#' @export
base64url_decode <- function(text){
  text <- fix_padding(chartr('-_', '+/', text))
  base64_decode(text)
}



# Ensures base64 length is a multiple of 4
fix_padding <- function(text){
  text <- gsub("[\r\n]", "", text)[[1]]
  mod <- nchar(text) %% 4;
  if(mod > 0){
    padding <- paste(rep("=", (4 - mod)), collapse = "")
    text <- paste0(text, padding)
  }
  text
}
