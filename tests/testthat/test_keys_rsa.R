context("Test RSA formats")

# Read secret key and public key
sk1 <- read_key("../keys/id_rsa")
pk1 <- read_pubkey("../keys/id_rsa.pub")

test_that("reading protected keys", {
  if(fips_mode()){
    expect_error(read_key("../keys/id_rsa.pw", password = "test"), "FIPS")
  } else {
    expect_error(read_key("../keys/id_rsa.pw", password = ""), "bad")
    sk2 <- read_key("../keys/id_rsa.pw", password = "test")
    expect_equal(sk1, sk2)
  }

  sk3 <- read_key("../keys/id_rsa.openssh")
  sk4 <- read_key("../keys/id_rsa.openssh.pw", password = "test")
  expect_equal(sk1, sk3)
  expect_equal(sk1, sk4)
})

test_that("reading public key formats", {
  pk2 <- read_pubkey("../keys/id_rsa.pem")
  pk3 <- read_pubkey("../keys/id_rsa.pub")
  pk4 <- read_pubkey("../keys/id_rsa.sshpub")
  pk5 <- read_pubkey("../keys/id_rsa.sshpem2")
  pk6 <- as.list(sk1)$pubkey
  expect_equal(pk1, pk2)
  expect_equal(pk1, pk3)
  expect_equal(pk1, pk4)
  expect_equal(pk1, pk5)
  expect_equal(pk1, pk6)
})

test_that("legacy pkcs1 format", {
  expect_equal(sk1, read_key(write_pkcs1(sk1)))
  skip_if(fips_mode())
  expect_equal(sk1, read_key(write_pkcs1(sk1, password = 'test'), password = 'test'))
  expect_equal(pk1, read_pubkey(write_pkcs1(pk1)))
  expect_error(read_key(write_pkcs1(sk1, password = 'test'), password = ''))
})


test_that("pubkey ssh fingerprint", {
  fp <- paste(as.list(pk1)$fingerprint, collapse = "")
  expect_equal(fp, "d2cc4e49782bb98861990f7f3979cdcae7909b52ec08d5d8e223137a25705a27")
  pk7 <- read_pubkey(readLines("../keys/authorized_keys")[2])
  expect_equal(pk1, pk7)
  pk8 <- read_pubkey(write_ssh(pk1))
  expect_equal(pk1, pk8)
})

test_that("signatures", {
  # SHA1 signature
  msg <- readBin("../keys/message", raw(), 100)
  sig <- readBin("../keys/message.sig.rsa.sha1", raw(), 1000)
  expect_equal(signature_create(msg, sha1, sk1), sig)
  expect_true(signature_verify(msg, sig, sha1, pk1))

  # SHA256 signature
  sig <- readBin("../keys/message.sig.rsa.sha256", raw(), 1000)
  expect_equal(signature_create(msg, sha256, sk1), sig)
  expect_true(signature_verify(msg, sig, sha256, pk1))

  # MD5 signature
  skip_if(fips_mode())
  sig <- readBin("../keys/message.sig.rsa.md5", raw(), 1000)
  expect_equal(signature_create(msg, md5, sk1), sig)
  expect_true(signature_verify(msg, sig, md5, pk1))
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
  sig <- signature_create("../keys/message", sha256, "../keys/id_rsa")
  writeBin(sig, tmp <- tempfile())
  expect_true(signature_verify("../keys/message", tmp, sha256, "../keys/id_rsa.pub"))
})

test_that("rsa_keygen works", {
  key <- rsa_keygen(1024)
  expect_is(key, "rsa")
  expect_equal(as.list(key)$size, 1024)
  rm(key)

  key <- rsa_keygen(2048)
  expect_is(key, "rsa")
  expect_equal(as.list(key)$size, 2048)
  rm(key)
})

# Cleanup
rm(sk1, pk1)
