rand_pseudo_bytes <- function(length = 1){
  .Call(R_RAND_pseudo_bytes, length, TRUE)
}

rand_bytes <- function(length = 1){
  .Call(R_RAND_pseudo_bytes, length, FALSE)
}