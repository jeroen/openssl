context("Test the length of the output of various algorithms.")

test_that("MD5 outputs a 32-character hash", {

  expect_that(nchar(hash("foo","md5")), equals(32))

})

test_that("SHA1 outputs a 40-character hash", {

  expect_that(nchar(hash("foo","sha1")), equals(40))

})

test_that("SHA256 outputs a 64-character hash", {

  expect_that(nchar(hash("foo","sha256")), equals(64))

})

test_that("SHA512 outputs a 128-character hash", {

  expect_that(nchar(hash("foo","sha512")), equals(128))

})
