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

validate_openssh <- function(str){
  is.character(str) && grepl("^(ssh-dss|ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\\d+)\\s+", str[1])
}

parse_openssh <- function(buf){
  text <- rawToChar(buf)
  if(!validate_openssh(text))
    stop("Unsupported ssh key id format: ", substring(text, 1, 15))

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
    "ecdsa-sha2-nistp384" = ecdsa_build(out),
    "ecdsa-sha2-nistp521" = ecdsa_build(out),
    stop("Unsupported keytype: ", header)
  )
}

#' @useDynLib openssl R_rsa_pubkey_build
rsa_build <- function(keydata){
  exp <- keydata[[2]]
  mod <- keydata[[3]]
  .Call(R_rsa_pubkey_build, exp, mod)
}

#' @useDynLib openssl R_dsa_pubkey_build
dsa_build <- function(keydata){
  p <- keydata[[2]]
  q <- keydata[[3]]
  g <- keydata[[4]]
  y <- keydata[[5]]
  .Call(R_dsa_pubkey_build, p, q, g, y)
}

#' @useDynLib openssl R_ecdsa_pubkey_build
ecdsa_build <- function(keydata){
  curve_name <- rawToChar(keydata[[2]])
  nist_name <- switch(curve_name,
    "nistp256" = "P-256",
    "nistp384" = "P-384",
    "nistp521" = "P-521",
    stop("Unsupported curve type: ", curve_name)
  );
  ec_point <- keydata[[3]]
  if(ec_point[1] != 0x04)
    stop("Invalid ecdsa format (not uncompressed?)")
  ec_point <- ec_point[-1];
  curve_size <- length(ec_point)/2
  x <- utils::head(ec_point, curve_size)
  y <- utils::tail(ec_point, curve_size)
  .Call(R_ecdsa_pubkey_build, x, y, nist_name);
}

ed25519_build <- function(keydata){
  structure(keydata[[2]], class = c("pubkey", "ed25519"))
}
