#' Default keypair
#'
#' The default key can be configured using environment variable \code{USER_KEY}
#' which points to the user (private) key. If unset it defaults to \code{"~/.ssh/id_rsa"}.
#' The \code{my_pubkey} function derives the corresponding public key.
#'
#' @export
#' @rdname my_key
my_key <- function(){
  path <- Sys.getenv("DEFAULT_KEY", "~/.ssh/id_rsa")
  if(!file.exists(path))
    stop("No suitable default key found.")
  read_key(path)
}

#' @export
#' @rdname my_key
my_pubkey <- function(){
  key <- my_key()
  as.list(key)$pubkey
}
