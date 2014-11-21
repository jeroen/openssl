#' @rdname rand_bytes
#' @export
rand_num <- function(n = 1){
  # 64 bit double requires 8 bytes.
  x <- matrix(as.numeric(rand_bytes(n*8)), ncol = 8)
  as.numeric(x %*% 256^-(1:8))
}
