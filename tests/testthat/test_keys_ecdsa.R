context("Test ECDSA 256 formats")

if(openssl_config()$ec){

# Read secret key and public key
sk1 <- read_key("../keys/id_ecdsa")
pk1 <- read_pubkey("../keys/id_ecdsa.pub")

test_that("reading protected keys", {
  if(fips_mode()){
    expect_error(read_key("../keys/id_ecdsa.pw", password = "test"), "FIPS")
  } else {
    expect_error(read_key("../keys/id_ecdsa.pw", password = NULL), "bad")
    sk2 <- read_key("../keys/id_ecdsa.pw", password = "test")
    expect_equal(sk1, sk2)
  }
  sk3 <- read_key("../keys/id_ecdsa.openssh")
  sk4 <- read_key("../keys/id_ecdsa.openssh.pw", password = "test")

  expect_equal(sk1, sk3)
  expect_equal(sk1, sk4)
})

test_that("reading public key formats", {
  pk2 <- read_pubkey("../keys/id_ecdsa.pem")
  pk3 <- read_pubkey("../keys/id_ecdsa.pub")
  pk4 <- read_pubkey("../keys/id_ecdsa.sshpub")
  pk5 <- as.list(sk1)$pubkey
  expect_equal(pk1, pk2)
  expect_equal(pk1, pk3)
  expect_equal(pk1, pk4)
  expect_equal(pk1, pk5)
})

test_that("legacy pkcs1 format", {
  expect_equal(sk1, read_key(write_pkcs1(sk1)))
  skip_if(fips_mode())
  expect_equal(sk1, read_key(write_pkcs1(sk1, password = 'test'), password = 'test'))
  #expect_equal(pk1, read_pubkey(write_pkcs1(pk1)))
  expect_error(read_key(write_pkcs1(sk1, password = 'test'), password = ''))
})

test_that("pubkey ssh fingerprint", {
  fp <- paste(as.list(pk1)$fingerprint, collapse = "")
  expect_equal(fp, "53492762ee530db92cc0c651f4454803d474f3a5bef6cac301cc8f3aac5d7f9e")
  pk5 <- read_pubkey(readLines("../keys/authorized_keys")[3])
  expect_equal(pk1, pk5)
  pk6 <- read_pubkey(write_ssh(pk1))
  expect_equal(pk1, pk6)
})

test_that("signatures", {
  # ecdsa does not support MD5
  msg <- readBin("../keys/message", raw(), 100)

  # SHA1 signature
  sig <- readBin("../keys/message.sig.ecdsa.sha1", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha1, pk1))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))

  sig <- signature_create(msg, sha1, sk1)
  expect_true(signature_verify(msg, sig, sha1, pk1))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))

  # SHA256 signature
  sig <- readBin("../keys/message.sig.ecdsa.sha256", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha256, pk1))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))

  sig <- signature_create(msg, sha256, sk1)
  expect_true(signature_verify(msg, sig, sha256, pk1))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))
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
  sig <- signature_create("../keys/message", sha256, "../keys/id_ecdsa")
  writeBin(sig, tmp <- tempfile())
  expect_true(signature_verify("../keys/message", tmp, sha256, "../keys/id_ecdsa.pub"))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))
})

test_that("ec_keygen works", {
  key <- ec_keygen("P-256")
  expect_equal(as.list(key)$size, 256)
  expect_equal(as.list(key)$data$curve, "P-256")
  rm(key)
})

# Cleanup
rm(sk1, pk1)

} else {
  cat("ec not supported")
}

