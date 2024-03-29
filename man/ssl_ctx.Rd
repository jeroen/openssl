% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/sslctx.R
\name{ssl_ctx}
\alias{ssl_ctx}
\alias{ssl_ctx_add_cert_to_store}
\alias{ssl_ctx_set_verify_callback}
\alias{ssl_ctx_curl_version_match}
\title{Hooks to manipulate the SSL context for curl requests}
\usage{
ssl_ctx_add_cert_to_store(ssl_ctx, cert)

ssl_ctx_set_verify_callback(ssl_ctx, cb)

ssl_ctx_curl_version_match()
}
\arguments{
\item{ssl_ctx}{pointer object to the SSL context provided in the
ssl_ctx_function callback.}

\item{cert}{certificate object, e.g from \link{read_cert} or \link{download_ssl_cert}.}

\item{cb}{callback function with 1 parameter (the server certificate)
and which returns TRUE (for proceed) or FALSE (for abort).}
}
\description{
These functions allow for manipulating the SSL context from inside the
\href{https://curl.se/libcurl/c/CURLOPT_SSL_CTX_FUNCTION.html}{CURLOPT_SSL_CTX_FUNCTION}
callback using the curl R package. Note that this is not fully portable and will
only work on installations that use matching versions of libssl (see details).
It is recommended to only use this locally and if what you need cannot be
accomplished using standard libcurl TLS options, e.g. those listed in
\code{curl::curl_options('ssl')} or \code{curl::curl_options('tls')}.
}
\details{
Curl allows for setting an \link[curl:curl_options]{option} called \code{ssl_ctx_function}:
this is a callback function that is triggered during the TLS initiation, before
any https connection has been made. This serves as a hook to let you manipulate
the TLS configuration (called \code{SSL_CTX} for historical reasons), in order to
control how to curl will validate the authenticity of server certificates for
upcoming TLS connections.

Currently we provide 2 such functions: \link{ssl_ctx_add_cert_to_store} injects a
custom certificate into the trust-store of the current TLS connection. But
most flexibility is provided via \link{ssl_ctx_set_verify_callback} which allows
you to override the function that is used by validate if a server certificate
should be trusted. The callback will receive one argument \code{cert} and has to
return \code{TRUE} or \code{FALSE} to decide if the cert should be trusted.

By default libcurl re-uses connections, hence the cert validation is only
performed in the first request to a given host. Subsequent requests use the
already established TLS connection. For testing, it can be useful to set
\code{forbid_reuse} in order to make a new connection for each request, as done
in the examples below.
}
\section{System compatibility}{
Passing the SSL_CTX between the curl and openssl R packages only works if they
are linked to the same version of libssl. Use \link{ssl_ctx_curl_version_match}
to test if this is the case. On Debian / Ubuntu you need to build the R curl
package against \code{libcurl4-openssl-dev}, which is usually the case. On Windows
you would need to set \code{CURL_SSL_BACKEND=openssl} in your \verb{~/.Renviron} file.
On MacOS things are complicated because it uses LibreSSL instead of OpenSSL
by default. You can make it work by compiling the curl R package from source
against the homebrew version of curl and then then set \code{CURL_SSL_BACKEND=openssl}
in your \verb{~/.Renviron} file. If your curl and openssl R packages use different
versions of libssl, the examples may segfault due to ABI incompatibility of the
SSL_CTX structure.
}

\examples{
\dontrun{
# Example 1: accept your local snakeoil https cert
mycert <- openssl::download_ssl_cert('localhost')[[1]]

# Setup the callback
h <- curl::new_handle(ssl_ctx_function = function(ssl_ctx){
  ssl_ctx_add_cert_to_store(ssl_ctx, mycert)
}, verbose = TRUE, forbid_reuse = TRUE)

# Perform the request
req <- curl::curl_fetch_memory('https://localhost', handle = h)

# Example 2 using a custom verify function
verify_cb <- function(cert){
  id <- cert$pubkey$fingerprint
  cat("Server cert from:", as.character(id), "\n")
  TRUE # always accept cert
}

h <- curl::new_handle(ssl_ctx_function = function(ssl_ctx){
  ssl_ctx_set_verify_callback(ssl_ctx, verify_cb)
}, verbose = TRUE, forbid_reuse = TRUE)

# Perform the request
req <- curl::curl_fetch_memory('https://localhost', handle = h)
}
}
