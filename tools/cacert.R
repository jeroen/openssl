# Download a recent CA bundle at build time. This is not fatal: at runtime
# ca_bundle() first looks for a system CA bundle anyway.
url <- "https://curl.se/ca/cacert.pem"
dest <- "inst/cacert.pem"
tmp <- tempfile(fileext = ".pem")
ok <- tryCatch({
  download.file(url, tmp, quiet = TRUE, mode = "wb")
  any(grepl("BEGIN CERTIFICATE", readLines(tmp, warn = FALSE), fixed = TRUE))
}, error = function(e) FALSE, warning = function(w) FALSE)
if(isTRUE(ok)){
  dir.create("inst", showWarnings = FALSE)
  file.copy(tmp, dest, overwrite = TRUE)
  cat("Downloaded CA bundle from", url, "\n")
} else {
  cat("Could not download CA bundle from", url, "(no internet?). Using only the system CA bundle.\n")
}
unlink(tmp)
