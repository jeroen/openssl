context("Test DSA formats")

# Read secret key and public key
sk1 <- read_key("../keys/id_dsa")
pk1 <- read_pubkey("../keys/id_dsa.pub")

test_that("reading protected keys", {
  if(fips_mode()){
    expect_error(read_key("../keys/id_dsa.pw", password = "test"), "FIPS")
  } else {
    expect_error(read_key("../keys/id_dsa.pw", password = ""), "bad")
    sk2 <- read_key("../keys/id_dsa.pw", password = "test")
    expect_equal(sk1, sk2)
  }
  sk3 <- read_key("../keys/id_dsa.openssh")
  sk4 <- read_key("../keys/id_dsa.openssh.pw", password = "test")

  expect_equal(sk1, sk3)
  expect_equal(sk1, sk4)
})

test_that("reading public key formats", {
  pk2 <- read_pubkey("../keys/id_dsa.pem")
  pk3 <- read_pubkey("../keys/id_dsa.pub")
  pk4 <- read_pubkey("../keys/id_dsa.sshpub")
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
  expect_equal(fp, "80e814f3f747a6427e2ab1c659ecbf3edcbeecc26039e7bcd207553619aec410")
  pk5 <- read_pubkey(readLines("../keys/authorized_keys")[1])
  expect_equal(pk1, pk5)
  pk6 <- read_pubkey(write_ssh(pk1))
  expect_equal(pk1, pk6)
})

test_that("SHA1 signatures", {
  # SHA1 signature
  skip_on_redhat()
  msg <- readBin("../keys/message", raw(), 100)
  sig <- readBin("../keys/message.sig.dsa.sha1", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha1, pk1))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))

  sig <- signature_create(msg, sha1, sk1)
  expect_true(signature_verify(msg, sig, sha1, pk1))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))
})

test_that("SHA256 signatures", {
  # SHA256 signature
  msg <- readBin("../keys/message", raw(), 100)
  sig <- readBin("../keys/message.sig.dsa.sha256", raw(), 1000)
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
  expect_equal(sk1, read_key(write_openssh_pem(sk1, tempfile())))
  expect_equal(pk1, read_pubkey(write_openssh_pem(sk1, tempfile())))
})

test_that("roundtrip der format", {
  expect_equal(pk1, read_pubkey(write_der(pk1), der = TRUE))
  expect_equal(sk1, read_key(write_der(sk1), der = TRUE))
  expect_equal(pk1, read_pubkey(write_der(pk1, tempfile()), der = TRUE))
  expect_equal(sk1, read_key(write_der(sk1, tempfile()), der = TRUE))
})

test_that("signature path interface", {
  sig <- signature_create("../keys/message", sha256, "../keys/id_dsa")
  writeBin(sig, tmp <- tempfile())
  expect_true(signature_verify("../keys/message", tmp, sha256, "../keys/id_dsa.pub"))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))
})

test_that("dsa_keygen works", {
  if(!fips_mode()){
    key <- dsa_keygen(1024)
    expect_is(key, "dsa")
    expect_equal(as.list(key)$size, 1024)
    rm(key)
  }

  key <- dsa_keygen(2048)
  expect_is(key, "dsa")
  expect_equal(as.list(key)$size, 2048)
  rm(key)
})

# Cleanup
rm(sk1, pk1)
