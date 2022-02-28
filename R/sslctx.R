#' Hooks to setup the SSL context for curl
#'
#' Hooks to manipulate the SSL context inside the `CURLOPT_SSL_CTX_FUNCTION`
#' callback in the curl package.
#'
#' By default libcurl re-uses connections, hence the cert validation is only
#' performed in the first request to a given host. Subsequent requests use the
#' already established TLS connection. For testing, it can be useful to set
#' `forbid_reuse` to use new connection for each request, as done in the examples.
#'
#' Passing the SSL_CTX between the curl and openssl R packages only works if they
#' are linked to the same version of openssl. Use `curl_openssl_version_match()`
#' to test if this is the case. On Debian / Ubuntu it will work if curl was built
#' against `libcurl4-openssl-dev`, which is usually the case. On Windows you need
#' to set `CURL_SSL_BACKEND=openssl` to your `~/.Renviron` file. On MacOS it is
#' more complicated because it does not use OpenSSL by default. You can make it
#' work by compiling the curl R package from source against the homebrew version
#' of curl and then set `CURL_SSL_BACKEND=openssl` in your `~/.Renviron` file. If
#' your curl and openssl R packages use different versions of libssl, the examples
#' below' may segfault due to ABI incompatibility of the SSL_CTX object.
#'
#' @examples \dontrun{
#' # Example: accept your local snakeoil https cert
#' mycert <- openssl::download_ssl_cert('localhost')[[1]]
#'
#' # Setup the callback
#' h <- curl::new_handle(ssl_ctx_function = function(ssl_ctx){
#'   ssl_ctx_add_cert_to_store(ssl_ctx, mycert)
#' }, verbose = TRUE, forbid_reuse = TRUE)
#'
#' # Perform the request
#' req <- curl::curl_fetch_memory('https://localhost', handle = h)
#'
#' # Example using a custom verify function
#' verify_cb <- function(cert){
#'   id <- cert$pubkey$fingerprint
#'   cat("Server cert from:", as.character(id), "\n")
#'   TRUE # always accept cert
#' }
#'
#' h <- curl::new_handle(ssl_ctx_function = function(ssl_ctx){
#'   ssl_ctx_set_verify_callback(ssl_ctx, verify_cb)
#' }, verbose = TRUE, forbid_reuse = TRUE)
#'
#' # Perform the request
#' req <- curl::curl_fetch_memory('https://localhost', handle = h)
#' }
#' @export
#' @name ssl_ctx
#' @rdname ssl_ctx
#' @useDynLib openssl R_ssl_ctx_add_cert_to_store
#' @param ssl_ctx the payload you get from curl in ssl_ctx_function
#' @param cert object returned by [read_cert]
ssl_ctx_add_cert_to_store <- function(ssl_ctx, cert){
  stopifnot(inherits(ssl_ctx, 'ssl_ctx'))
  .Call(R_ssl_ctx_add_cert_to_store, ssl_ctx, cert)
}

#' @export
#' @rdname ssl_ctx
#' @useDynLib openssl R_ssl_ctx_set_verify_callback
#' @param cb callback function with at least 1 parameter (the server certificate).
ssl_ctx_set_verify_callback <- function(ssl_ctx, cb){
  stopifnot(inherits(ssl_ctx, 'ssl_ctx'))
  .Call(R_ssl_ctx_set_verify_callback, ssl_ctx, cb)
}

#' @export
#' @rdname ssl_ctx
curl_openssl_version_match <- function(){
  x <- get_openssl_version(openssl::openssl_config()$version)
  y <- get_openssl_version(curl::curl_version()$ssl_version)
  return(length(x) && length(y) && identical(x,y))
}

get_openssl_version <- function(x){
  x <- gsub("\\(.*\\)", "", tolower(x))
  x <- gsub("/", " ", x, fixed = TRUE)
  m <- regexpr('openssl.[0-9.]+', x)
  regmatches(x, m)
}
