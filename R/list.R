#' @export
as.list.key <- function(key, ...){
  pubkey <- derive_pubkey(key)
  pk <- as.list(pubkey)
  list(
    type = pk$type,
    pubkey = pubkey,
    data = decompose(key)
  )
}

#' @export
as.list.pubkey <- function(pubkey, ...){
  ssh <- unlist(unname(fpdata(pubkey)))
  type <- ifelse(inherits(pubkey, "ed25519"), "ed25519", pubkey_type(pubkey))
  list(
    type = type,
    fingerprint = md5(ssh),
    data = decompose(pubkey)
  )
}

#' @export
as.list.cert <- function(cert, ...){
  pubkey <- cert_pubkey(cert)
  list (
    pubkey = pubkey
  )
}
