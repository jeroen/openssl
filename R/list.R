#' @export
as.list.key <- function(x, ...){
  key <- x
  pubkey <- derive_pubkey(key)
  pk <- as.list(pubkey)
  list(
    type = pk$type,
    pubkey = pubkey,
    data = decompose(key)
  )
}

#' @export
as.list.pubkey <- function(x, ...){
  pubkey <- x
  ssh <- unlist(unname(fpdata(pubkey)))
  type <- ifelse(inherits(pubkey, "ed25519"), "ed25519", pubkey_type(pubkey))
  list(
    type = type,
    fingerprint = md5(ssh),
    data = decompose(pubkey)
  )
}

#' @export
as.list.cert <- function(x, ...){
  cert <- x
  info <- cert_info(cert)
  info$pubkey <- cert_pubkey(cert)
  info
}
