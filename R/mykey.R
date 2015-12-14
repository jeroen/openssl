#' Default keypair
#'
#' Set a default keypair via \code{USER_KEY} and \code{USER_PUKBEY} variables.
#'
#' The \code{my_key()} function checks environment variable \code{USER_KEY} for a
#' path to a private keyfile. If unset it defaults to \code{"~/.ssh/id_rsa"}.
#'
#' The \code{my_pubkey()} function first tries \code{USER_PUBKEY} and if unset
#' it checks for \code{USER_KEY} to derive the corresponding pubkey. If both are
#' unset it defaults to \code{"~/.ssh/id_rsa.pub"}.
#'
#' @export
#' @rdname my_key
#' @examples # Set random RSA key as default
#' key <- rsa_keygen()
#' write_pem(key, tmp <- tempfile(), password = "")
#' rm(key)
#' Sys.setenv("USER_KEY" = tmp)
#'
#' # Check the new keys
#' print(my_key())
#' print(my_pubkey())
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
