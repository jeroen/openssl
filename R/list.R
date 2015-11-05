#' @export
as.list.key <- function(key, ...){
  pubkey <- derive_pubkey(key)
  ssh <- unlist(unname(fpdata(pubkey)))
  list(
    fingerprint = md5(ssh),
    type = pubkey_type(pubkey),
    pubkey = pubkey,
    ssh = ssh
  )
}
