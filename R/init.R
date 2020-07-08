.onAttach <- function(libname, pkg){
  conf <- openssl_config()
  version <- conf$version
  if(isTRUE(conf$fips))
    version <- paste(version, "(FIPS)")
  packageStartupMessage(paste("Linking to:", version))
}
