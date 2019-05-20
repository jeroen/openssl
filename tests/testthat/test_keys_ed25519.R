context("Test ED25519 formats")

if(openssl_config()$x25519){

# Read secret key and public key
sk1 <- read_key("../keys/id_ed25519")
pk1 <- read_pubkey("../keys/id_ed25519.pub")

test_that("reading protected keys", {
  sk2 <- read_key("../keys/id_ed25519.pw", password = "test")
  sk3 <- read_key("../keys/id_ed25519.openssh")
  sk4 <- read_key("../keys/id_ed25519.openssh.pw", password = "test")
  expect_equal(sk1, sk2)
  expect_equal(sk1, sk3)
  expect_equal(sk1, sk4)
  expect_error(read_key("../keys/id_ed25519.pw", password = NULL), "bad")
})

test_that("reading public key formats", {
  pk2 <- read_pubkey("../keys/id_ed25519.pem")
  pk3 <- read_pubkey("../keys/id_ed25519.pub")
  pk4 <- read_pubkey("../keys/id_ed25519.pub")
  pk5 <- as.list(sk1)$pubkey
  expect_equal(pk1, pk2)
  expect_equal(pk1, pk3)
  expect_equal(pk1, pk4)
  expect_equal(pk1, pk5)
})

test_that("pubkey ssh fingerprint", {
  fp <- paste(as.list(pk1)$fingerprint, collapse = "")
  expect_equal(fp, "2c9bea2e9a4ce1fb4438d854b27204b3")
})

test_that("signatures", {
  # TODO
})

test_that("roundtrip pem format", {
  expect_equal(pk1, read_pubkey(write_pem(pk1)))
  expect_equal(sk1, read_key(write_pem(sk1, password = NULL)))
  expect_equal(pk1, read_pubkey(write_pem(pk1, tempfile())))
  expect_equal(sk1, read_key(write_pem(sk1, tempfile(), password = NULL)))
})

test_that("roundtrip der format", {
  expect_equal(pk1, read_pubkey(write_der(pk1), der = TRUE))
  expect_equal(sk1, read_key(write_der(sk1), der = TRUE))
  expect_equal(pk1, read_pubkey(write_der(pk1, tempfile()), der = TRUE))
  expect_equal(sk1, read_key(write_der(sk1, tempfile()), der = TRUE))
})

test_that("signature path interface", {
  #
})

test_that("ec_keygen works", {
  key <- ed25519_keygen()
  expect_equal(as.list(key)$size, 256)
  expect_length(as.list(key)$data, 32)
  rm(key)
})

# Cleanup
rm(sk1, pk1)

} else {
  cat("x25519 not supported")
}

