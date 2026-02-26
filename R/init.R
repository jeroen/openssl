libssl_version_number <- NULL
.onLoad <- function(libname, pkg) {
  try({
    ver <- openssl_config()$version
    m <- regexec('[0-9]+\\.[0-9]+\\.[0-9]+', ver)
    libssl_version_number <<- numeric_version(regmatches(ver, m)[[1]])
  })
  if(.Platform$OS.type == 'windows'){
    # See https://github.com/jeroen/bcrypt/issues/7
    if(file.exists("C:\\Windows\\System32\\bcrypt.dll")){
      dyn.load("C:\\Windows\\System32\\bcrypt.dll")
    }
  }
}

.onAttach <- function(libname, pkg){
  conf <- openssl_config()
  version <- conf$version
  if(isTRUE(conf$fips))
    version <- paste(version, "(FIPS)")
  packageStartupMessage(paste("Linking to:", version))
}
