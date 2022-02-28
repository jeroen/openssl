#' Hooks to setup the SSL context for curl
#'
#' Manipulate the SSL context inside the `CURLOPT_SSL_CTX_FUNCTION` function in
#' curl. Important: this only works if R packages curl and openssl are dynamically
#' linked to the same libssl, e.g. when using `libcurl4-openssl-dev` on Ubuntu.
#' It will almost surely crash for R packages with statically linked libssl.
#'
#' By default libcurl re-uses connections, hence the cert validation is only
#' triggered in the first request. After that it re-uses the established TLS
#' connection. For debugging you may want to set `forbid_reuse` to create a
#' new connection for each request.
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
#' req <- curl::curl_fetch_memory('https://localhost/ocpu/info', handle = h)
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
#' req <- curl::curl_fetch_memory('https://localhost/ocpu/info', handle = h)
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
