parse_ssh2 <- function(text){
  # extract the ssh2 pubkey text block
  text <- paste(text, collapse = "\n")
  regex <- "([-]+ BEGIN SSH2 PUBLIC KEY [-]+)(.*?)([-]+ END SSH2 PUBLIC KEY [-]+)"
  m <- regexpr(regex, text)
  if(m < 0)
    stop("Failed to find SSH2 public key header/footer")

  # strip off text headers and comments
  text <- regmatches(text, m)
  text <- sub("([-]+ BEGIN SSH2 PUBLIC KEY [-]+)[\\s]*", "", text)
  text <- sub("([-]+ END SSH2 PUBLIC KEY [-]+)[\\s]*", "", text)
  text <- sub("Comment(.*?)\\n", "", text)

  # construct the actual key
  rsa_build(text)
}

parse_openssh <- function(text){
  text <- paste(text, collapse = "")
  text <- sub("^ssh-rsa\\s+", "", text)
  text <- sub("\\s+.*$", "", text)
  rsa_build(text)
}

#' @useDynLib openssl R_rsa_build
rsa_build <- function(b64_text){
  # parse ssh binary format
  keydata <- base64_decode(b64_text)
  con <- rawConnection(keydata, open = "rb")
  on.exit(close(con))

  # read rsa header value
  len <- readBin(con, 1L, endian = "big")
  header <- rawToChar(readBin(con, raw(), len))
  if (!identical(header, "ssh-rsa"))
    stop("Unsupported SSH2 public key - expected 'ssh-rsa', found: ", header)

  # read exponent value
  len <- readBin(con, 1L, endian = "big")
  expdata <- readBin(con, raw(), len)

  # read modulo value
  len <- readBin(con, 1L, endian = "big")
  moddata <- readBin(con, raw(), len)

  # build RSA key
  bin <- .Call(R_rsa_build, expdata, moddata)
  structure(bin, class = c("rsa", "pubkey"))
}

# inverse of rsa_build
#' @useDynLib openssl R_rsa_decompose
rsa_decompose <- function(key){
  stopifnot(is.raw(key))
  out <- .Call(R_rsa_decompose, key)
  structure(out, names = c("exp", "mod"))
}

#' @export
rsa_fingerprint <- function(pubkey){
  input <- c(list(charToRaw("ssh-rsa")), rsa_decompose(pubkey))
  out <- lapply(input, function(x){
    c(writeBin(length(x), raw(), endian = "big"), x)
  })
  md5(unlist(unname(out)))
}
