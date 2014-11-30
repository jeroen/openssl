library(cryptohash)
library(openssl)
library(digest)
library(microbenchmark)

# Test digest
digest_vector <- function(x, algo){
  vapply(x, digest, character(1), algo=algo, serialize=FALSE, USE.NAMES=FALSE)
}

# Make sure we are on the same page
x1 <- digest_vector(c("foo", "bar"), "md5")
x2 <- cryptohash(c("foo", "bar"), "md5")
x3 <- openssl::digest(c("foo", "bar"), "md5")
stopifnot(identical(x1, x2), identical(x1, x3))
rm(x1, x2, x3)

test_all <- function(algo){
  # random object
  x <- rep(readLines(system.file("DESCRIPTION", package="base")), 1000)

  microbenchmark(
    digest_vector(x, algo),
    cryptohash(x, algo),
    openssl::digest(x, algo),
    times=10
  )
}

test_all("md5")
test_all("sha1")
test_all("sha256")
