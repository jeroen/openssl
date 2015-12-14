#' Default keypair
#'
#' The \code{my_key()} function looks for environment variable \code{USER_KEY} with a
#' path to a private keyfile. If unset it defaults to \code{"~/.ssh/id_rsa"}. The
#' \code{my_pubkey()} function looks for environment variable \code{USER_PUBKEY} which
#' defaults to \code{"~/.ssh/id_rsa.pub"}. If neither exists it will also try \code{my_key()}
#' and derive the corresponding public key.
#'
#' @export
#' @rdname my_key
my_key <- function(){
  path <- Sys.getenv("USER_KEY", "~/.ssh/id_rsa")
  if(!file.exists(path))
    stop("No suitable user key found.")
  read_key(path)
}

#' @export
#' @rdname my_key
my_pubkey <- function(){
  path <- Sys.getenv("USER_PUBKEY", Sys.getenv("USER_KEY", "~/.ssh/id_rsa.pub"))
  if(file.exists(path))
    return(read_pubkey(path))

  # alternatively derive pubkey from key
  key <- my_key()
  as.list(key)$pubkey
}
