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
  data <- decompose(pubkey)
  type <- ifelse(inherits(pubkey, "ed25519"), "ed25519", pubkey_type(pubkey))
  header <- switch(type,
   "rsa" = "ssh-rsa",
   "dsa" = "ssh-dss",
   "ed25519" = "ssh-ed25519",
   "ecdsa" = paste0("ecdsa-sha2-nistp", substring(data$curve, 3)),
   stop("Unsupported keytype: ", type)
  )
  fp <- unlist(unname(fpdata(pubkey)))
  list(
    type = type,
    ssh = paste(header, base64_encode(fp)),
    fingerprint = md5(fp),
    data = data
  )
}

#' @export
as.list.cert <- function(x, ...){
  cert <- x
  info <- cert_info(cert)
  info$pubkey <- cert_pubkey(cert)
  info
}
