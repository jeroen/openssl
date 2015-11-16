context("Test ECDSA 521 formats")

# Read secret key and public key
sk1 <- read_key("../keys/id_ecdsa521")
pk1 <- read_pubkey("../keys/id_ecdsa521.pub")

test_that("reading protected keys", {
  sk2 <- read_key("../keys/id_ecdsa521.pw", password = "test")
  expect_equal(sk1, sk2)
  expect_error(read_key("../keys/id_ecdsa521.pw", password = NULL), "bad password")
})

test_that("reading public key formats", {
  pk2 <- read_pubkey("../keys/id_ecdsa521.pem")
  pk3 <- read_pubkey("../keys/id_ecdsa521.pub")
  pk4 <- as.list(sk1)$pubkey
  expect_equal(pk1, pk2)
  expect_equal(pk1, pk3)
  expect_equal(pk1, pk4)
})

test_that("pubkey ssh fingerprint", {
  fp <- paste(as.list(pk1)$fingerprint, collapse = "")
  expect_equal(fp, "904d4c50be879bf0557af96b9935f1c2")
})

test_that("signatures", {
  # ecdsa521 does not support MD5
  msg <- readBin("../keys/message", raw(), 100)

  # SHA1 signature
  sig <- readBin("../keys/message.sig.ecdsa521.sha1", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha1, pk1))

  sig <- signature_create(msg, sha1, sk1)
  expect_true(signature_verify(msg, sig, sha1, pk1))

  # SHA256 signature
  sig <- readBin("../keys/message.sig.ecdsa521.sha256", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha256, pk1))

  sig <- signature_create(msg, sha256, sk1)
  expect_true(signature_verify(msg, sig, sha256, pk1))
})

test_that("signature path interface", {
  sig <- signature_create("../keys/message", sha256, "../keys/id_ecdsa521")
  writeBin(sig, tmp <- tempfile())
  expect_true(signature_verify("../keys/message", tmp, sha256, "../keys/id_ecdsa521.pub"))
})

# Cleanup
rm(sk1, pk1)