#' Parsing keys and certificates
#'
#' The \code{read_key} function (private keys) and \code{read_pubkey} (public keys)
#' support both SSH pubkey format and OpenSSL PEM format (base64 data with a \code{--BEGIN}
#' and \code{---END} header), and automatically convert where necessary. The functions assume
#' a single key per file except for \code{read_cert_bundle} which supports PEM files
#' with multiple certificates.
#'
#' Most versions of OpenSSL support at least RSA, DSA and ECDSA keys. Certificates must
#' conform to the X509 standard.
#'
#' The \code{password} argument is needed when reading keys that are protected with a
#' passphrase. It can either be a string containing the passphrase, or a custom calback
#' function that will be called by OpenSSL to read the passphrase. The function should
#' take one argument (a string with a message) and return a string. The default is to
#' use \code{readline} which will prompt the user in an interactive R session.
#'
#' @export
#' @param file Either a path to a file, a connection, or literal data (a string for
#' pem/ssh format, or a raw vector in der format)
#' @param password A string or callback function to read protected keys
#' @param der set to \code{TRUE} if \code{file} is in binary DER format
#' @return An object of class \code{cert}, \code{key} or \code{pubkey} which holds the data
#' in binary DER format and can be decomposed using \code{as.list}.
#' @rdname read_key
#' @seealso \link{download_ssl_cert}
#' @examples \dontrun{# Read private key
#' key <- read_key("~/.ssh/id_rsa")
#' as.list(key)
#'
#' # Read public key
#' pubkey <- read_pubkey("~/.ssh/id_rsa.pub")
#' as.list(pubkey)
#'
#' # Read certificates
#' txt <- readLines("http://curl.haxx.se/ca/cacert.pem")
#' bundle <- read_cert_bundle(txt)
#' print(bundle)
#' }
read_key <- function(file, password = askpass, der = is.raw(file)){
  buf <- read_input(file)
  key <- if(isTRUE(der)){
    parse_der_key(buf)
  } else if(length(grepRaw("BEGIN OPENSSH PRIVATE KEY", buf, fixed = TRUE))){
    stop("OpenSSL does not support them fancy OPENSSH bcrypt/ed25519 keys")
  } else if(is_pubkey_str(buf)){
    stop("Input is a public key. Use read_pubkey() to read")
  } else {
    info <- parse_pem(buf)
    name <- info$name
    if(!length(name) || !nchar(name))
      stop("Failed to parse private key: unknown format")
    if(grepl("PUBLIC", name))
      stop("Input is a public key. Use read_pubkey() to read")
    if(grepl("CERTIFICATE", name))
      stop("Input is a certificate. Use read_cert() to read.")
    if(!grepl("PRIVATE", name))
      stop("Invalid input: ", name)
    parse_pem_key(buf, password)
  }
  structure(key, class = c("key", pubkey_type(derive_pubkey(key))))
}

#' @export
#' @rdname read_key
read_pubkey <- function(file, der = is.raw(file)){
  if(inherits(file, "key") || inherits(file, "cert"))
    return(as.list(file)$pubkey)
  if(is_pubkey_str(file))
    file <- textConnection(file)
  buf <- read_input(file)
  key <- if(isTRUE(der)){
    parse_der_pubkey(buf)
  } else if(length(grepRaw("BEGIN SSH2 PUBLIC KEY", buf, fixed = TRUE))){
    parse_ssh_pem(buf)
  } else if(is_pubkey_str(buf)){
    parse_openssh(buf)
  } else {
    info <- parse_pem(buf)
    name <- info$name
    if(!length(name) || !nchar(name)){
      stop("Failed to parse public key: unknown format")
    } else if(grepl("RSA PUBLIC KEY", name)){
      parse_legacy_pubkey(buf)
    } else if(grepl("PUBLIC", name)){
      parse_pem_pubkey(buf)
    } else if(grepl("PRIVATE", name)){
      derive_pubkey(read_key(buf, der = FALSE))
    } else if(grepl("CERTIFICATE", name)){
      cert_pubkey(parse_pem_cert(buf))
    } else {
      stop("Invalid PEM type: ", name)
    }
  }
  if(is.null(attr(key, "class")))
    class(key) <- c("pubkey", pubkey_type(key))
  key
}

#' @export
#' @rdname read_key
read_cert <- function(file, der = is.raw(file)){
  buf <- read_input(file)
  cert <- if(der){
    parse_der_cert(buf)
  } else {
    parse_pem_cert(buf)
  }
  structure(cert, class = "cert")
}

#' @export
#' @rdname read_key
read_cert_bundle <- function(file){
  buf <- read_input(file)
  lapply(split_pem(buf), read_cert)
}

read_input <- function(x){
  if(is.raw(x)){
    x
  } else if(inherits(x, "connection")){
    if(summary(x)$text == "text") {
      charToRaw(paste(readLines(x), collapse = "\n"))
    } else {
      out <- raw();
      while(length(buf <- readBin(x, raw(), 1e6))){
        out <- c(out, buf)
      }
      out
    }
  } else if(is.character(x) && length(x) == 1 && !grepl("\n", x) && !is_pubkey_str(x)){
    x <- normalizePath(path.expand(x), mustWork = TRUE)
    info <- file.info(x)
    stopifnot(!info$isdir)
    readBin(x, raw(), info$size)
  } else if(is.character(x)) {
    charToRaw(paste(x, collapse = "\n"))
  } else {
    stop("file must be connection, raw vector or file path")
  }
}

#' @useDynLib openssl R_parse_pem
parse_pem <- function(input){
  stopifnot(is.raw(input))
  out <- .Call(R_parse_pem, input)
  if(is.null(out)) return(out)
  structure(out, names = c("name", "header", "data"))
}

#' @useDynLib openssl R_parse_pem_key
parse_pem_key <- function(buf, password = readline){
  .Call(R_parse_pem_key, buf, password)
}

#' @useDynLib openssl R_parse_der_key
parse_der_key <- function(buf){
  .Call(R_parse_der_key, buf)
}

#' @useDynLib openssl R_parse_pem_pubkey
parse_pem_pubkey <- function(buf){
  .Call(R_parse_pem_pubkey, buf)
}

#' @useDynLib openssl R_parse_pem_pkcs1
parse_legacy_pubkey <- function(buf){
  .Call(R_parse_pem_pkcs1, buf)
}

#' @useDynLib openssl R_parse_der_pubkey
parse_der_pubkey <- function(buf){
  .Call(R_parse_der_pubkey, buf)
}

#' @useDynLib openssl R_parse_pem_cert
parse_pem_cert <- function(buf, password){
  .Call(R_parse_pem_cert, buf)
}

#' @useDynLib openssl R_parse_der_cert
parse_der_cert <- function(buf){
  .Call(R_parse_der_cert, buf)
}

#' @useDynLib openssl R_derive_pubkey
derive_pubkey <- function(key){
  pk <- .Call(R_derive_pubkey, key)
  structure(pk, class = c("pubkey", class(key)[2]))
}

#' @useDynLib openssl R_cert_pubkey
cert_pubkey <- function(cert){
  pubkey <- .Call(R_cert_pubkey, cert)
  type <- pubkey_type(pubkey)
  structure(pubkey, class = c("pubkey", type))
}

# Detect openssh2 public key strings
is_pubkey_str <- function(str){
  if(is.character(str))
    str <- charToRaw(paste(str, collapse = "\n"))
  as.logical(length(grepRaw("^(ssh|ecdsa)-[a-z0-9-]+\\s+", str, ignore.case = TRUE)))
}

# Split a pem file with multiple keys/certs
split_pem <- function(text) {
  if(is.raw(text))
    text <- rawToChar(text)
  pattern <- "(-+BEGIN)(.+?)(-+END)(.+?)(-+)"
  m <- gregexpr(pattern, text)
  regmatches(text, m)[[1]]
}

#' @export
print.key <- function(x, ...){
  pk <- derive_pubkey(x)
  fp <- fingerprint(pk)
  cat(sprintf("[%d-bit %s private key]\n", pubkey_bitsize(pk), pubkey_type(pk)))
  cat(sprintf("md5: %s\n", paste(fp, collapse = ":")))
}

#' @export
print.pubkey <- function(x, ...){
  fp <- fingerprint(x)
  type <- class(x)[2]
  cat(sprintf("[%d-bit %s public key]\n", pubkey_bitsize(x), pubkey_type(x)))
  cat(sprintf("md5: %s\n", paste(fp, collapse = ":")))
}

#' @export
print.cert <- function(x, ...){
  subject <- cert_info(x)$subject
  cname <- regmatches(subject, regexpr("CN ?=[^,]*", subject))
  cname <- ifelse(length(cname), gsub("CN ?=", "", cname), "")
  cat(sprintf("[x509 certificate] %s\n", cname))
  cat(sprintf("md5: %s\n", paste(md5(x), collapse = ":")))
  cat(sprintf("sha1: %s\n", paste(sha1(x), collapse = ":")))
}

path_or_raw <- function(x){
  if(is.raw(x)) return(x)
  if(is.character(x) && length(x) == 1){
    path <- normalizePath(x, mustWork = TRUE)
    bin <- readBin(path, raw(), file.info(path)$size)
    return(bin)
  }
  stop("x must be raw data vector or path to file on disk.")
}
