context("Test the actual output values of various algorithms.")

test_that("MD5 outputs appropriate values for possible inputs", {

  expect_that(hash("foo","md5"), equals("acbd18db4cc2f85cedef654fccc4a4d8"))

})

test_that("SHA1 outputs appropriate values for possible inputs", {

  expect_that(hash("foo","sha1"), equals("0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"))

})

test_that("SHA256 outputs appropriate values for possible inputs", {

  expect_that(hash("foo","sha256"), equals("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"))

})

test_that("SHA512 outputs appropriate values for possible inputs", {

  expect_that(hash("foo","sha512"), equals("f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"))

})
