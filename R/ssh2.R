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
  ssh_pubkey_from_string(text)
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
  ssh_pubkey_from_string(text)
}

# parse ssh binary format
ssh_pubkey_from_string <- function(b64text){
  ssh_build_pubkey(base64_decode(b64text))
}

ssh_parse_data <- function(data){
  con <- rawConnection(data, open = "rb")
  on.exit(close(con))
  out <- list()
  while(length(buf <- read_con_buf(con))){
    out <- c(out, list(buf))
  }
  return(out)
}

ssh_build_pubkey <- function(keydata){
  out <- ssh_parse_data(keydata)
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

ssh_build_privkey <- function(keydata){
  out <- ssh_parse_data(keydata)
  header <- rawToChar(out[[1]])
  switch(header,
         "ssh-dss" = dsa_build_priv(out),
         "ssh-rsa" = rsa_build_priv(out),
         "ssh-ed25519" = ed25519_build_priv(out),
         "ecdsa-sha2-nistp256" = ecdsa_build_priv(out),
         "ecdsa-sha2-nistp384" = ecdsa_build_priv(out),
         "ecdsa-sha2-nistp521" = ecdsa_build_priv(out),
         stop("Unsupported keytype: ", header)
  )
}

dsa_build_priv <- function(keydata){
  p <- bignum(keydata[[2]])
  q <- bignum(keydata[[3]])
  g <- bignum(keydata[[4]])
  y <- bignum(keydata[[5]])
  x <- bignum(keydata[[6]])
  structure(dsa_key_build(p, q, g, y, x), class = c("key", "dsa"))
}

rsa_build_priv <- function(keydata){
  n <- bignum(keydata[[2]])
  e <- bignum(keydata[[3]])
  d <- bignum(keydata[[4]])
  qi <- bignum(keydata[[5]])
  p <- bignum(keydata[[6]])
  q <- bignum(keydata[[7]])
  structure(rsa_key_build(e, n, p, q, d, qi), class = c("key", "rsa"))
}

rsa_build <- function(keydata){
  exp <- keydata[[2]]
  mod <- keydata[[3]]
  structure(rsa_pubkey_build(exp, mod), class = c("pubkey", "rsa"))
}

dsa_build <- function(keydata){
  p <- keydata[[2]]
  q <- keydata[[3]]
  g <- keydata[[4]]
  y <- keydata[[5]]
  structure(dsa_pubkey_build(p, q, g, y), class = c("pubkey", "dsa"))
}

ed25519_build_priv <- function(keydata){
  key <- read_raw_key_ed25519(utils::head(keydata[[3]], 32))
  structure(key, class = c("key", "ed25519"))
}

ed25519_build <- function(keydata){
  pubkey <- read_raw_pubkey_ed25519(keydata[[2]])
  structure(pubkey, class = c("pubkey", "ed25519"))
}

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
  structure(ecdsa_pubkey_build(x, y, nist_name), class = c("pubkey", "ecdsa"))
}

ecdsa_build_priv <- function(keydata){
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
  secret <- keydata[[4]]
  ecdsa_key_build(x, y, secret, nist_name)
}

# Assume we can just take the first key
parse_openssh_key_pubkey <- function(input){
  keydata <- parse_openssh_key_data(input)
  ssh_build_pubkey(keydata$pubdata[[1]])
}

# Assume we can just take the first key
parse_openssh_key_private <- function(input, password){
  data <- parse_openssh_key_data(input)
  ciphername <- data$ciphername
  kdfname <- data$kdfname
  input <- if(kdfname == "none") {
    data$privdata
  } else if(kdfname == "bcrypt") {
    kdfopt <- parse_openssh_kdfoptions(data$kdfoptions)
    if(is.function(password)){
      password <- password("Please enter your private key passphrase")
    } else if(!is.character(password)){
      stop("Password is not a string or function")
    }
    cipher <- strsplit(ciphername, '-', fixed = TRUE)[[1]]
    mode <- cipher[2]
    keysize <- as.integer(sub("aes-?", "", cipher[1])) / 8
    ivsize <- ifelse(identical(mode, "gcm"), 12, 16)
    kdfsize <- as.integer(keysize + ivsize)
    key_iv <- bcrypt_pbkdf(password, salt = kdfopt$salt, rounds = kdfopt$rounds, size = kdfsize)
    aes_decrypt(data$privdata, key = key_iv[seq_len(keysize)], iv = key_iv[-seq_len(keysize)], mode)
  } else {
    stop(sprintf("Unsupported key encryption: %s (%s)", kdfname, ciphername))
  }
  if(!identical(input[1:4], input[5:8]))
    stop("Check failed, invalid passphrase?")
  ssh_build_privkey(input[-seq_len(8)])
}

parse_openssh_kdfoptions <- function(input){
  con <- rawConnection(input, open = "rb")
  on.exit(close(con))
  list(
    salt = read_con_buf(con),
    rounds = readBin(con, 1L, endian = 'big')
  )
}

parse_openssh_key_data <- function(input){
  pemdata <- parse_pem(input)
  data <- pemdata[[1]]$data
  con <- rawConnection(data, open = "rb")
  on.exit(close(con))
  header <- readBin(con, "")
  ciphername <- read_con_string(con)
  kdfname <- read_con_string(con)
  kdfoptions <- read_con_buf(con)
  count <- readBin(con, 1L, endian = "big")
  pubdata <- lapply(seq_len(count), function(i){read_con_buf(con)})
  privdata <- read_con_buf(con)
  stopifnot(is.null(read_con_buf(con)))
  list (
    header = header,
    ciphername = ciphername,
    kdfname = kdfname,
    kdfoptions = kdfoptions,
    count = count,
    pubdata = pubdata,
    privdata = privdata
  )
}

read_con_buf <- function(con){
  size <- readBin(con, 1L, endian = "big")
  if(!length(size))
    return(NULL)
  if(size == 0)
    return(raw())
  buf <- readBin(con, raw(), size)
  # see padding_start() below for 16909060L
  # padding spec: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD
  if(length(buf) < size){
    if(size == 16909060L && identical(buf, as.raw(seq_len(length(buf)) + 4))){
      return(NULL)
    } else {
      stop("Trailing trash found in buffer")
    }
  }
  return(buf)
}

# Proof that 16909060L equals padding
padding_start <- function(){
  data <- as.raw(1:4)
  con <- rawConnection(data, open = "rb")
  on.exit(close(con))
  readBin(con, integer(), endian = 'big')
}

read_con_string <- function(con){
  rawToChar(read_con_buf(con))
}
