#' @export
as.list.key <- function(key, ...){
  pubkey <- derive_pubkey(key)
  pk <- as.list(pubkey)
  list(
    type = pk$type,
    fingerprint = pk$fingerprint,
    pubkey = pubkey
  )
}

#' @export
as.list.pubkey <- function(pubkey, ...){
  ssh <- unlist(unname(fpdata(pubkey)))
  list(
    type = pubkey_type(pubkey),
    fingerprint = md5(ssh),
    ssh = ssh
  )
}

#' @export
as.list.cert <- function(cert, ...){
  pubkey <- cert_pubkey(cert)
  list(
    pubkey = pubkey
  )
}
