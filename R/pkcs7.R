#' @export
#' @rdname pkcs12
read_pkcs7 <- function(file, der = is.raw(file)){
  buf <- read_input(file)
  if(!isTRUE(der)){
    buf <- parse_pem_pkcs7(buf)
  }
  data <- structure(parse_der_pkcs7(buf), names = c("certs", "crl"))
  # Don't return the CRL, nobody seems to use that
  lapply(data$certs, read_cert)
}

#' @useDynLib openssl R_parse_der_pkcs7
parse_der_pkcs7 <- function(buf){
  .Call(R_parse_der_pkcs7, buf)
}

#' @useDynLib openssl R_parse_pem_pkcs7
parse_pem_pkcs7 <- function(buf){
  .Call(R_parse_pem_pkcs7, buf)
}

#' @export
#' @rdname pkcs12
#' @useDynLib openssl R_write_pkcs7
#' @param der set to TRUE for binary files and FALSE for PEM files
write_pkcs7 <- function(ca, path = NULL){
  ca <- if(inherits(ca, "cert")) {
    list(ca)
  } else {
    lapply(ca, read_cert)
  }
  bin <- .Call(R_write_pkcs7, ca)
  if(is.null(path)) return(bin)
  writeBin(bin, path)
  invisible(path)
}
