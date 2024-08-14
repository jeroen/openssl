# See https://github.com/jeroen/openssl/issues/125
skip_on_redhat <- function(){
  skip_if(grepl("redhat", R.version$platform))
}
