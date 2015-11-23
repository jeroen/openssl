#' Big number arithmetic
#'
#' Basic operations for working with large integers. The \code{bignum}
#' funtion converts a positive integer, string or raw vector into a bignum type.
#' All basic \link{Arithmetic} and \link{Comparison} operators such as
#' \code{+}, \code{-}, \code{*}, \code{^}, \code{\%\%}, \code{\%/\%}, \code{==},
#' \code{!=}, \code{<}, \code{<=}, \code{>} and \code{>=} are implemented for
#' bignum objects. The
#' \href{https://en.wikipedia.org/wiki/Modular_exponentiation}{Modular exponenent}
#' (\code{a^b \%\% m}) can be calculated using \code{\link{bignum_mod_exp}}
#' when \code{b} is too large for calculating \code{a^b} directly.
#'
#' @export
#' @name bignum
#' @rdname bignum
#' @param x an integer, string (hex or dec) or raw vector
#' @param a bignum value for \code{(a^b \%\% m)}
#' @param b bignum value for \code{(a^b \%\% m)}
#' @param m bignum value for \code{(a^b \%\% m)}
#' @param hex set to TRUE to parse strings as hex rather than decimal notation
#' @useDynLib openssl R_parse_bignum
#' @examples # create a bignum
#' x <- bignum(123L)
#' y <- bignum("123456789123456789")
#' z <- bignum("D41D8CD98F00B204E9800998ECF8427E", hex = TRUE)
#'
#' # Basic arithmetic
#' div <- z %/% y
#' mod <- z %% y
#' z2 <- div * y + mod
#' stopifnot(z2 == z)
#' stopifnot(div < z)
bignum <- function(x, hex = FALSE){
  if(inherits(x, "bignum"))
    return(x)
  stopifnot(is.raw(x) || is.character(x) || is.numeric(x))
  if(is.numeric(x)){
    if(is_positive_integer(x)){
      x <- formatC(x, format = "fg")
    } else {
      stop("Cannot convert to bignum: x must be positive integer, character or raw", call. = FALSE)
    }
  }
  if(is.character(x)){
    if(identical(x, "0")){
      # special case always valid
    } else if(isTRUE(hex)){
      if(!grepl("^([a-fA-F0-9]{2})+$", x))
        stop("Value '", x, "' is not valid hex string", call. = FALSE)
    } else {
      if(!grepl("^[0-9]+$", x))
        stop("Value '", x, "' is not valid integer", call. = FALSE)
    }
  }
  .Call(R_parse_bignum, x, hex)
}

bn <- bignum

#' @export
print.bignum <- function(x, hex = FALSE, ...){
  cat("[b]", as.character.bignum(x, hex = hex))
}

#' @export
#' @useDynLib openssl R_bignum_as_character
as.character.bignum <- function(x, hex = FALSE, ...){
  .Call(R_bignum_as_character, x, hex)
}

#' @export
#' @useDynLib openssl R_bignum_add
`+.bignum` <- function(x, y){
  .Call(R_bignum_add, bn(x), bn(y))
}

#' @export
#' @useDynLib openssl R_bignum_subtract
`-.bignum` <- function(x, y){
  x <- bn(x)
  y <- bn(y)
  stopifnot(x >= y)
  .Call(R_bignum_subtract, x, y)
}

#' @export
#' @useDynLib openssl R_bignum_multiply
`*.bignum` <- function(x, y){
  .Call(R_bignum_multiply, bn(x), bn(y))
}

#' @export
#' @useDynLib openssl R_bignum_exp
`^.bignum` <- function(x, y){
  .Call(R_bignum_exp, bn(x), bn(y))
}

#' @export
#' @useDynLib openssl R_bignum_devide
`%/%.bignum` <- function(x, y){
  .Call(R_bignum_devide, bn(x), bn(y))
}


# Doesn't help because R always evaluates 'x' to determine dispatch method
#' @export
`%%.bignum` <- function(x, y){
  xcall = substitute(x)
  if(length(xcall) == 3 && identical(xcall[[1]], quote(`^`))){
    a <- eval(xcall[[2]])
    b <- eval(xcall[[3]])
    bignum_mod_exp(a, b, y)
  } else {
    bignum_mod(x, y)
  }
}

#' @export
#' @useDynLib openssl R_bignum_compare
`>.bignum` <- function(x, y){
  identical(1L, .Call(R_bignum_compare, bn(x), bn(y)));
}

#' @export
#' @useDynLib openssl R_bignum_compare
`<.bignum` <- function(x, y){
  identical(-1L, .Call(R_bignum_compare, bn(x), bn(y)));
}

#' @export
#' @useDynLib openssl R_bignum_compare
`==.bignum` <- function(x, y){
  identical(0L, .Call(R_bignum_compare, bn(x), bn(y)));
}

#' @export
`!=.bignum` <- function(x, y){
  !identical(0L, .Call(R_bignum_compare, bn(x), bn(y)));
}

#' @export
`>=.bignum` <- function(x, y){
  .Call(R_bignum_compare, bn(x), bn(y)) > -1L;
}

#' @export
`<=.bignum` <- function(x, y){
  .Call(R_bignum_compare, bn(x), bn(y)) < 1L;
}

#' @export
`/.bignum` <- function(x, y){
  stop("Use integer division %/% and modulo %% for dividing bignum objects", call. = FALSE)
}

#' @useDynLib openssl R_bignum_mod
bignum_mod <- function(x, y){
  .Call(R_bignum_mod, x, y)
}

#' @export
#' @rdname bignum
#' @useDynLib openssl R_bignum_mod_exp
bignum_mod_exp <- function(a, b, m){
  .Call(R_bignum_mod_exp, a, b, m)
}

#' @useDynLib openssl R_bignum_bits
bignum_bits <- function(x){
  .Call(R_bignum_bits, x)
}

is_positive_integer <- function(x)  {
  if(x < 0)
    return(FALSE)
  if(is.integer(x))
    return(TRUE)
  tol <- sqrt(.Machine$double.eps)
  if(x < 2^53 && abs(x - round(x)) < tol)
    return(TRUE)
  return(FALSE)
}
