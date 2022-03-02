#' Hooks to manipulate the SSL context for curl requests
#'
#' These functions allow for manipulating the SSL context from inside the
#' [CURLOPT_SSL_CTX_FUNCTION](https://curl.se/libcurl/c/CURLOPT_SSL_CTX_FUNCTION.html)
#' callback using the curl R package. Note that this is not fully portable and will
#' only work on installations that use matching versions of libssl (see details).
#' It is recommended to only use this locally and if what you need cannot be
#' accomplished using standard libcurl TLS options, e.g. those listed in
#' `curl::curl_options('ssl')` or `curl::curl_options('tls')`.
#'
#' Curl allows for setting an [option][curl::curl_options] called `ssl_ctx_function`:
#' this is a callback function that is triggered during the TLS initiation, before
#' any https connection has been made. This serves as a hook to let you manipulate
#' the TLS configuration (called `SSL_CTX` for historical reasons), in order to
#' control how to curl will validate the authenticity of server certificates for
#' upcoming TLS connections.
#'
#' Currently we provide 2 such functions: [ssl_ctx_add_cert_to_store] injects a
#' custom certificate into the trust-store of the current TLS connection. But
#' most flexibility is provided via [ssl_ctx_set_verify_callback] which allows
#' you to override the function that is used by validate if a server certificate
#' should be trusted. The callback will receive one argument `cert` and has to
#' return `TRUE` or `FALSE` to decide if the cert should be trusted.
#'
#' By default libcurl re-uses connections, hence the cert validation is only
#' performed in the first request to a given host. Subsequent requests use the
#' already established TLS connection. For testing, it can be useful to set
#' `forbid_reuse` in order to make a new connection for each request, as done
#' in the examples below.
#'
#' # System compatibility
#'
#' Passing the SSL_CTX between the curl and openssl R packages only works if they
#' are linked to the same version of libssl. Use [ssl_ctx_curl_version_match]
#' to test if this is the case. On Debian / Ubuntu you need to build the R curl
#' package against `libcurl4-openssl-dev`, which is usually the case. On Windows
#' you would need to set `CURL_SSL_BACKEND=openssl` in your `~/.Renviron` file.
#' On MacOS things are complicated because it uses LibreSSL instead of OpenSSL
#' by default. You can make it work by compiling the curl R package from source
#' against the homebrew version of curl and then then set `CURL_SSL_BACKEND=openssl`
#' in your `~/.Renviron` file. If your curl and openssl R packages use different
#' versions of libssl, the examples may segfault due to ABI incompatibility of the
#' SSL_CTX structure.
#'
#' @examples \dontrun{
#' # Example 1: accept your local snakeoil https cert
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
#' # Example 2 using a custom verify function
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
#' @param ssl_ctx pointer object to the SSL context provided in the
#' ssl_ctx_function callback.
#' @param cert certificate object, e.g from [read_cert] or [download_ssl_cert].
ssl_ctx_add_cert_to_store <- function(ssl_ctx, cert){
  stopifnot(inherits(ssl_ctx, 'ssl_ctx'))
  .Call(R_ssl_ctx_add_cert_to_store, ssl_ctx, cert)
}

#' @export
#' @rdname ssl_ctx
#' @useDynLib openssl R_ssl_ctx_set_verify_callback
#' @param cb callback function with 1 parameter (the server certificate)
#' and which returns TRUE (for proceed) or FALSE (for abort).
ssl_ctx_set_verify_callback <- function(ssl_ctx, cb){
  stopifnot(inherits(ssl_ctx, 'ssl_ctx'))
  .Call(R_ssl_ctx_set_verify_callback, ssl_ctx, cb)
}

#' @export
#' @rdname ssl_ctx
ssl_ctx_curl_version_match <- function(){
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
