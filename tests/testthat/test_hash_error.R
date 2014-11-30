context("Test the error handlers for hash functions")

test_that("hash detects invalid algorithms", {

  expect_that(hash("foo","turnip"), throws_error(regexp = "Unknown cryptographic algorithm", fixed = TRUE))

})

test_that("rawhash detects invalid algorithms", {

  expect_that(rawhash("foo","turnip"), throws_error(regexp = "Unknown cryptographic algorithm", fixed = TRUE))

})

test_that("hash detects non-vector inputs", {

  expect_that(hash(list(c("foo","bar"),"baz"),"md5"), gives_warning(regexp = "must be a vector. Attempting to convert.", fixed = TRUE))

})

test_that("Vectors containing NA values are detected", {

  expect_that(hash(NA,"md5"),
              gives_warning(regexp = "x contains NA values (possibly from conversion)", fixed = TRUE))

})
