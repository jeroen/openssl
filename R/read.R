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
#' passphrase. It can either be a string containing the passphrase, or a custom callback
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
#' str(key)
#'
#' # Read public key
#' pubkey <- read_pubkey("~/.ssh/id_rsa.pub")
#' str(pubkey)
#'
#' # Read certificates
#' txt <- readLines("https://curl.haxx.se/ca/cacert.pem")
#' bundle <- read_cert_bundle(txt)
#' print(bundle)
#' }
read_key <- function(file, password = askpass, der = is.raw(file)){
  buf <- read_input(file)
  key <- if(isTRUE(der)){
    parse_der_key(buf)
  } else if(length(grepRaw("BEGIN OPENSSH PRIVATE KEY", buf, fixed = TRUE))){
    parse_openssh_key_private(buf, password = password)
  } else if(is_pubkey_str(buf)){
    stop("Input is a public key. Use read_pubkey() to read")
  } else {
    names <- pem_names(buf)
    if(!length(names) || !any(nchar(names) > 0))
      stop("Failed to parse private key PEM file")
    if(any(grepl("PUBLIC", names)))
      stop("Input is a public key. Use read_pubkey() to read")
    if(any(grepl("CERTIFICATE", names)))
      stop("Input is a certificate. Use read_cert() to read.")
    if(!any(grepl("PRIVATE", names)))
      stop("Invalid input: ", names)
    if(any(grepl("RSA PRIVATE", names))){
      # Try the modern format first, PKCS1 is very uncommon nowadays
      tryCatch(parse_pem_key(buf, password), error = function(e){
        parse_legacy_key(buf, password)
      })
    } else {
      parse_pem_key(buf, password)
    }
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
  } else if(length(grepRaw("BEGIN OPENSSH PRIVATE KEY", buf, fixed = TRUE))){
    parse_openssh_key_pubkey(buf)
  } else if(is_pubkey_str(buf)){
    parse_openssh(buf)
  } else {
    names <- pem_names(buf)
    if(!length(names) || !any(nchar(names) > 0)){
      stop("Failed to parse pubkey PEM file")
    } else if(any(grepl("RSA PUBLIC KEY", names))){
      parse_legacy_pubkey(buf)
    } else if(any(grepl("PUBLIC", names))){
      parse_pem_pubkey(buf)
    } else if(any(grepl("PRIVATE|PARAMETERS", names))){
      derive_pubkey(read_key(buf, der = FALSE))
    } else if(any(grepl("CERTIFICATE", names))){
      cert_pubkey(parse_pem_cert(buf))
    } else {
      stop("Invalid PEM type: ", names)
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
  if(is.character(x) && grepl("^https?://", x)){
    x <- url(x)
  }
  if(is.raw(x)){
    x
  } else if(inherits(x, "connection")){
    if(!isOpen(x)){
      open(x, "rb")
      on.exit(close(x))
    }
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

#' The `read_pem` function parses the PEM file into a header and a data payload. It
#' is mostly useful for debugging.
#' @export
#' @rdname read_key
read_pem <- function(file){
  buf <- read_input(file)
  out <- parse_pem(buf)
  data <- lapply(out, `[[`, "data")
  names <- vapply(out, `[[`, character(1), "name")
  structure(data, names = names)
}

#' @useDynLib openssl R_parse_pem
parse_pem <- function(input){
  stopifnot(is.raw(input))
  out <- .Call(R_parse_pem, input)
  lapply(out, structure, names = c("name", "header", "data"))
}

pem_names <- function(input){
  out <- parse_pem(input)
  vapply(out, `[[`, character(1), "name")
}

#' @useDynLib openssl R_parse_pem_key
parse_pem_key <- function(buf, password = readline){
  .Call(R_parse_pem_key, buf, password)
}

#' @useDynLib openssl R_parse_pem_key_pkcs1
parse_legacy_key <- function(buf, password){
  tryCatch({
    .Call(R_parse_pem_key_pkcs1, buf, password)
  }, error = function(e){
    parse_pem_key(buf, password)
  })
}

#' @useDynLib openssl R_parse_der_key
parse_der_key <- function(buf){
  .Call(R_parse_der_key, buf)
}

#' @useDynLib openssl R_parse_pem_pubkey
parse_pem_pubkey <- function(buf){
  .Call(R_parse_pem_pubkey, buf)
}

#' @useDynLib openssl R_parse_pem_pubkey_pkcs1
parse_legacy_pubkey <- function(buf){
  # It is a common problem that clients add the wrong header
  tryCatch({
    .Call(R_parse_pem_pubkey_pkcs1, buf)
  }, error = function(e){
    out <- gsub("RSA PUBLIC", "PUBLIC", rawToChar(buf), fixed = TRUE)
    parse_pem_pubkey(charToRaw(out))
  })
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
