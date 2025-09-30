# See https://github.com/jeroen/openssl/issues/125
skip_on_redhat <- function(){
  skip_if(any(grepl("fedora|redhat|rocky", c(osVersion, R.version$platform), ignore.case = TRUE)))
}
