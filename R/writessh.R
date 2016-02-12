#' @export
#' @rdname write_pem
#' @param pubkey a public key
#' @examples # Generate RSA keypair
#' key <- rsa_keygen()
#' pubkey <- as.list(key)$pubkey
#'
#' # Write to output formats
#' write_ssh(pubkey)
#' write_pem(pubkey)
#' write_pem(key, password = "super secret")
write_ssh <- function(pubkey, path = NULL){
  if(inherits(pubkey, "key"))
    pubkey <- derive_pubkey(pubkey)
  if(!inherits(pubkey, "pubkey"))
    stop("Invalid pubkey file.")
  str <- as.list(pubkey)$ssh
  if(is.null(path)) return(str)
  writeLines(str, path)
  invisible(path)
}

