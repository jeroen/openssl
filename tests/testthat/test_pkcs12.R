context("Test PKCS12 reader")

test_that("reading p12 certificates", {
  p1 <- read_pkcs12("../google.dk/wildcard-google.dk-chain.p12")

  expect_error(read_pkcs12("../google.dk/wildcard-google.dk-chain-password.p12", password = ""), "password")
  p2 <- read_pkcs12("../google.dk/wildcard-google.dk-chain-password.p12", password = "password")
  expect_identical(p1, p2)

  bundle <- read_cert_bundle("../google.dk/wildcard-google.dk-chain.pem")
  expect_identical(p1$ca, bundle)

  leaf <- read_cert("../google.dk/wildcard-google.dk-leaf.crt", der = TRUE)
  expect_identical(leaf, bundle[[1]])

})

test_that("reading p12 keys", {
  expect_error(read_pkcs12("../certigo/example-root.p12", password = ""), "password")
  b1 <- read_pkcs12("../certigo/example-root.p12", password = "password")
  c1 <- read_cert("../certigo/example-root.crt")
  expect_identical(b1$cert, c1)
  expect_identical(b1$cert$pubkey, b1$key$pubkey)

  expect_error(read_pkcs12("../certigo/example-leaf.p12", password = ""), "password")
  b2<- read_pkcs12("../certigo/example-leaf.p12", password = "password")
  c2 <- read_cert("../certigo/example-leaf.crt")
  expect_identical(b2$cert, c2)
  expect_identical(b2$cert$pubkey, b2$key$pubkey)

  if(isTRUE(openssl_config()$ec)){
    expect_error(read_pkcs12("../certigo/example-elliptic-sha1.p12", password = ""), "password")
    b3 <- read_pkcs12("../certigo/example-elliptic-sha1.p12", password = "password")
    c3 <- read_cert("../certigo/example-elliptic-sha1.crt")
    k3 <- read_key("../certigo/example-elliptic-sha1.key")
    expect_identical(b3$cert, c3)
    expect_identical(b3$key, k3)
    expect_identical(b3$cert$pubkey, b3$key$pubkey)
  }

})
