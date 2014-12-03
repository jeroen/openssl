context("Test the length of the output of various algorithms.")

test_that("MD4 outputs a 32-character hash", {

  expect_that(nchar(md4("foo")), equals(32))

})

test_that("MD5 outputs a 32-character hash", {

  expect_that(nchar(md5("foo")), equals(32))

})

test_that("ripemd160 outputs a 40-character hash", {

  expect_that(nchar(ripemd160("foo")), equals(40))

})

test_that("SHA1 outputs a 40-character hash", {

  expect_that(nchar(sha1("foo")), equals(40))

})


test_that("SHA256 outputs a 64-character hash", {

  expect_that(nchar(sha256("foo")), equals(64))

})

test_that("SHA512 outputs a 128-character hash", {

  expect_that(nchar(sha512("foo")), equals(128))

})
