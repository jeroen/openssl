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
x3 <- openssl::digest(c("foo", "bar"), "sha256")
stopifnot(identical(x1, x2), identical(x1, x3))
rm(x1, x2, x3)

test_all <- function(algo, n = 1){
  # random object
  str <- paste(readLines(file.path(Sys.getenv("R_HOME"), "COPYING")), collapse="\n")
  x <- rep(str, n)

  microbenchmark(
    digest_vector(x, algo),
    cryptohash::cryptohash(x, algo),
    openssl::digest(x, algo),
    times = 10
  )
}

# Non vectorized
test_all("md5")
test_all("sha1")
test_all("sha256")

# Vectorized
test_all("md5", 1000)
test_all("sha1", 1000)
test_all("sha256", 1000)
