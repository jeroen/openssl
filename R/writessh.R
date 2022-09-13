#' @export
#' @rdname write_pem
#' @param pubkey a public key
#' @examples # Generate RSA keypair
#' key <- rsa_keygen()
#' pubkey <- key$pubkey
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


# Inverse of ssh_parse_data
ssh_generate_buf <- function(data, header = NULL, padsize = NULL){
  con <- rawConnection(raw(0), "r+")
  on.exit(close(con))
  if(length(header))
    writeBin(header, con)
  lapply(data, function(buf){
    buf <- unclass(buf)
    if(is.integer(buf))
      return(writeBin(buf, con, endian = 'big'))
    if(is.character(buf))
      buf <- charToRaw(buf)
    stopifnot(is.raw(buf))
    len <- as.integer(length(buf))
    writeBin(len, con, endian = 'big')
    writeBin(buf, con, endian = 'big')
  })
  out <- rawConnectionValue(con)
  if(length(padsize)){
    len <- length(out)
    outlen <- padsize * (((len-1) %/% padsize) + 1)
    out <- c(out, as.raw(seq_len(outlen - len)))
  }
  out
}


#' @export
#' @rdname write_pem
#' @param key a private key
write_openssh_pem <- function(key, path = NULL){
  # For now no passwords supported yet
  # Spec: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
  stopifnot(inherits(key, "key"))
  payload <- c(privdata(key), "user@localhost")
  header <- rep(rand_bytes(4), 2)
  fields <- list (
    ciphername = "none",
    kdfname = "none",
    kdfoptions = "",
    count = 1L,
    pubdata = unlist(fpdata(key$pubkey)),
    privdata = ssh_generate_buf(payload, header = header, padsize = 32)
  )
  out <- ssh_generate_buf(fields, header = 'openssh-key-v1')
  str <- write_pem_data('OPENSSH PRIVATE KEY', out)
  #str <- paste0("-----BEGIN OPENSSH PRIVATE KEY-----\n", base64_encode(out), "\n-----END OPENSSH PRIVATE KEY-----\n")
  if(is.null(path)) return(str)
  writeLines(str, path)
  invisible(path)
}

#' @useDynLib openssl R_pem_write_data
write_pem_data <- function(name, data){
  stopifnot(is.character(name))
  stopifnot(is.raw(data))
  .Call(R_pem_write_data, name, data)
}
