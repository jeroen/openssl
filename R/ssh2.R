parse_ssh_pem <- function(buf){
  # extract the ssh2 pubkey text block
  text <- rawToChar(buf)
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
  ssh_build(text)
}

parse_openssh <- function(buf){
  text <- rawToChar(buf)
  if(!grepl("^(ssh-dss|ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)\\s+", text))
    stop("Unsupported ssh key id format: ", substring(text, 15))

  # Extract the base64 part
  text <- sub("^\\S+\\s+", "", text)
  text <- regmatches(text, regexpr("^\\S*", text))
  ssh_build(text)
}

# parse ssh binary format
ssh_build <- function(b64text){
  con <- rawConnection(base64_decode(b64text), open = "rb")
  on.exit(close(con))
  out <- list();
  while(length(size <- readBin(con, 1L, endian = "big"))){
    if(size == 0) break
    buf <- readBin(con, raw(), size)
    stopifnot(length(buf) == size)
    out <- c(out, list(buf))
  }

  # extract key format
  header <- rawToChar(out[[1]])
  switch(header,
    "ssh-dss" = dsa_build(out),
    "ssh-rsa" = rsa_build(out),
    "ssh-ed25519" = ed25519_build(out),
    "ecdsa-sha2-nistp256" = ecdsa_build(out),
    stop("Unsupported keytype: ", header)
  )
}

#' @useDynLib openssl R_rsa_build
rsa_build <- function(keydata){
  exp <- keydata[[2]]
  mod <- keydata[[3]]
  bin <- .Call(R_rsa_build, exp, mod)
  structure(bin, class = c("rsa", "pubkey"))
}

#' @useDynLib openssl R_dsa_build
dsa_build <- function(keydata){
  p <- structure(keydata[[2]], class = "bignum")
  q <- structure(keydata[[3]], class = "bignum")
  g <- structure(keydata[[4]], class = "bignum")
  y <- structure(keydata[[5]], class = "bignum")
  bin <- .Call(R_dsa_build, p, q, g, y)
  structure(bin, class = c("dsa", "pubkey"))
}

#' @useDynLib openssl R_ecdsa_build
ecdsa_build <- function(keydata){
  curve_name <- rawToChar(keydata[[2]])
  if(curve_name != "nistp256")
    warning("Unsupported curve: ", curve_name)
  ec_point <- keydata[[3]]
  if(ec_point[1] != 0x04)
    stop("Invalid ecdsa format (not uncompressed?)")
  ec_point <- ec_point[-1];
  curve_size <- length(ec_point)/2
  x <- structure(utils::head(ec_point, curve_size), class = "bignum")
  y <- structure(utils::tail(ec_point, curve_size), class = "bignum")
  bin <- .Call(R_ecdsa_build, x, y, curve_size);
  structure(bin, class = c("ecdsa", "pubkey"))
}

ed25519_build <- function(keydata){
  key <- keydata[[2]]
  structure(key, class = c("ed25519", "pubkey"))
}
