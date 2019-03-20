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
  ssh_build_raw(base64_decode(b64text))
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

ssh_build_raw <- function(data){
  out <- ssh_parse_data(data)

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

ed25519_build <- function(keydata){
  structure(keydata[[2]], class = c("pubkey", "ed25519"))
}

parse_openssh_key_pubkey <- function(input){
  keydata <- parse_openssh_key_data(input)
  ssh_build_raw(keydata$pubdata[[1]])
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
  number <- readBin(con, 1L, endian = "big")
  pubdata <- lapply(seq_len(number), function(i){read_con_buf(con)})
  privdata <- read_con_buf(con)
  stopifnot(is.null(read_con_buf(con)))
  list (
    header = header,
    ciphername = ciphername,
    kdfname = kdfname,
    kdfoptions = kdfoptions,
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
  stopifnot(length(buf) == size)
  return(buf)
}

read_con_string <- function(con){
  rawToChar(read_con_buf(con))
}
