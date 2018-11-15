#' Default key
#'
#' The default user key can be set in the \code{USER_KEY} variable and otherwise
#' is \code{~/.ssh/id_rsa}. Note that on Windows we treat `~` as the windows user
#' home (and not the documents folder).
#'
#' The \code{my_pubkey()} function looks for the public key by appending \code{.pub}
#' to the above key path. If this file does not exist, it reads the private key file
#' and automatically derives the corresponding pubkey. In the latter case the user
#' may be prompted for a passphrase if the private key is protected.
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
  path <- default_key()
  if(!file.exists(path))
    stop("No suitable user key found.")
  read_key(path)
}

#' @export
#' @rdname my_key
my_pubkey <- function(){
  path <- paste0(default_key(), ".pub")
  if(file.exists(path))
    return(read_pubkey(path))

  # alternatively derive pubkey from key
  key <- my_key()
  pubkey <- key$pubkey
  try(write_ssh(pubkey, path), silent = TRUE)
  pubkey
}

default_key <- function(){
  normalize_home(Sys.getenv("USER_KEY", "~/.ssh/id_rsa"))
}

normalize_home <- function(path = NULL){
  path <- as.character(path)
  if(is_windows()){
    homedir <- Sys.getenv('USERPROFILE')
    is_home <- grepl("^~", path)
    path[is_home] <- paste0(homedir, substring(path[is_home], 2))
  }
  normalizePath(path, mustWork = FALSE)
}

is_windows <- function(){
  .Platform$OS.type == "windows"
}
