context("Test pkcs12")

test_that("reading protected keys", {
  p1 <- read_pkcs12("../google.dk/wildcard-google.dk-chain.p12")
  p2 <- read_pkcs12("../google.dk/wildcard-google.dk-chain-password.p12", password = "password")
  expect_identical(p1, p2)

  bundle <- read_cert_bundle("../google.dk/wildcard-google.dk-chain.pem")
  expect_identical(p1$ca, bundle)

  leaf <- read_cert("../google.dk/wildcard-google.dk-leaf.crt", der = TRUE)
  expect_identical(leaf, bundle[[1]])
})
