#' @export
`[[.cert` <- function(x, y) as.list(x)[[y]]

#' @export
`[[.key` <- `[[.cert`

#' @export
`[[.pubkey` <- `[[.cert`


#' @export
`$.cert` <- `[[.cert`

#' @export
`$.key` <- `[[.cert`

#' @export
`$.pubkey` <- `[[.cert`


#' @export
`[.cert` <- function(x, y) as.list(x)[y]

#' @export
`[.key` <- `[.cert`

#' @export
`[.pubkey` <- `[.cert`


#' @export
names.cert <- function(x) names(as.list(x))

#' @export
names.key <- names.cert

#' @export
names.pubkey <- names.cert


#' @export
as.environment.cert <- function(x) as.environment(as.list(x))

#' @export
as.environment.key <- as.environment.cert

#' @export
as.environment.pubkey <- as.environment.cert


#' @export
#' @importFrom utils .DollarNames
.DollarNames.cert <- function(x, pattern = "") {
  x <- as.list(x)
  matches <- grep(pattern, names(x), value = TRUE)
  structure(matches,
            types = vapply(x[matches], typeof, character(1), USE.NAMES = FALSE))
}

#' @export
.DollarNames.key <- .DollarNames.cert

#' @export
.DollarNames.pubkey <- .DollarNames.cert


#' @export
str.cert <- function(object, ...) utils::str(as.list(object), ...)

#' @export
str.key <- str.cert

#' @export
str.pubkey <- function(object, ...){
  x <- as.list(object)
  x$ssh <- paste(substring(x$ssh, 1, getOption('width') - 30), "...")
  utils::str(x, ...)
}


### Not (yet?) implemented stuff

stopfun <- function(..., value){ stop("object cannot be modified", call. = FALSE) }

#' @export
`[<-.cert` <- stopfun

#' @export
`[<-.key` <- stopfun

#' @export
`[<-.pubkey` <- stopfun

#' @export
`[[<-.cert` <- stopfun

#' @export
`[[<-.key` <- stopfun

#' @export
`[[<-.pubkey` <- stopfun

#' @export
`$<-.cert` <- stopfun

#' @export
`$<-.key` <- stopfun

#' @export
`$<-.pubkey` <- stopfun
