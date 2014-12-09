library(cryptohash)
library(openssl)
library(digest)
library(microbenchmark)

# Test digest
digest_vector <- function(x, algo){
  vapply(x, digest::digest, character(1), algo=algo, serialize=FALSE, USE.NAMES=FALSE)
}

# Make sure we are on the same page
x1 <- digest_vector(c("foo", "bar"), "sha256")
x2 <- cryptohash(c("foo", "bar"), "sha256")
x3 <- sha256(c("foo", "bar"))
stopifnot(identical(x1, x2), identical(x1, x3))
rm(x1, x2, x3)

test_all <- function(n = 1){
  # random object
  str <- paste(readLines(file.path(Sys.getenv("R_HOME"), "COPYING")), collapse="\n")
  x <- rep(str, n)

  microbenchmark(
    digest_vector(x, "md5"),
    cryptohash::cryptohash(x, "md5"),
    md5(x),
    times = 10
  )
}

# Vectorized calls
test_all(1000)
