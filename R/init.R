libssl_version_number <- NULL
.onLoad <- function(libname, pkg) {
  try({
    ver <- openssl_config()$version
    m <- regexec('[0-9]+\\.[0-9]+\\.[0-9]+', ver)
    libssl_version_number <<- numeric_version(regmatches(ver, m)[[1]])
  })
}

.onAttach <- function(libname, pkg){
  conf <- openssl_config()
  version <- conf$version
  if(isTRUE(conf$fips))
    version <- paste(version, "(FIPS)")
  packageStartupMessage(paste("Linking to:", version))
}
