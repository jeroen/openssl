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
  expect_error(read_key("../keys/id_ed25519.pw", password = NULL), "bad|empty")
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
  expect_equal(fp, "e07a7f95a68c864c757942aac2a42ca3fb26f1f66cd37d6f77559b63847b9ade")
})

test_that("signatures", {
  skip_if(fips_mode())
  msg <- readBin("../keys/message", raw(), 100)

  # SHA1 signature
  sig <- readBin("../keys/message.sig.ed25519.sha1", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha1, pk1))

  sig <- signature_create(msg, sha1, sk1)
  expect_true(signature_verify(msg, sig, sha1, pk1))

  # Raw data signature
  sig <- readBin("../keys/message.sig.ed25519.raw", raw(), 1000)
  expect_true(signature_verify(msg, sig, NULL, pk1))

  sig <- signature_create(msg, NULL, sk1)
  expect_true(signature_verify(msg, sig, NULL, pk1))
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
  skip_if(fips_mode())
  sig <- signature_create("../keys/message", sha256, "../keys/id_ed25519")
  writeBin(sig, tmp <- tempfile())
  expect_true(signature_verify("../keys/message", tmp, sha256, "../keys/id_ed25519.pub"))
})

test_that("ec_keygen works", {
  skip_if(fips_mode())
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

