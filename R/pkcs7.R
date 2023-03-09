#' Encrypt/decrypt pkcs7 messages
#'
#' Encrypt or decrypt messages using PKCS7 smime format.
#' Note PKCS7 only supports RSA keys.
#'
#' @export
#' @rdname pkcs7
#' @useDynLib openssl R_pkcs7_encrypt
#' @param message text or raw vector with data to encrypt
#' @param cert the certificate with public key to use for encryption
#' @param pem convert output pkcs7 data to PEM format
pkcs7_encrypt <- function(message, cert, pem = TRUE){
  if(is.character(cert))
    cert <- read_cert(cert)
  if(is.character(message))
    message <- charToRaw(message)
  out <- .Call(R_pkcs7_encrypt, message, cert)
  if(!isTRUE(pem)){
    return(out)
  }
  write_pem(out)
}

#' @export
#' @rdname pkcs7
#' @seealso [encrypt_envelope]
#' @param input file path or string with PEM or raw vector with p7b data
#' @param key private key to decrypt data
#' @param der assume input is in DER format (rather than PEM)
#' @useDynLib openssl R_pkcs7_decrypt
pkcs7_decrypt <- function(input, key, der = is.raw(input)){
  if(length(key)) key <- read_key(key)
  buf <- read_input(input)
  if(!isTRUE(der)){
    buf <- parse_pem_pkcs7(buf)
  }
  .Call(R_pkcs7_decrypt, buf, key)
}
