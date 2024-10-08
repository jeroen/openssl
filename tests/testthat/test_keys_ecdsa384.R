context("Test ECDSA 384 formats")

if(openssl_config()$ec){

# Read secret key and public key
sk1 <- read_key("../keys/id_ecdsa384")
pk1 <- read_pubkey("../keys/id_ecdsa384.pub")

test_that("reading protected keys", {
  if(fips_mode()){
    expect_error(read_key("../keys/id_ecdsa384.pw", password = "test"), "FIPS")
  } else {
    expect_error(read_key("../keys/id_ecdsa384.pw", password = NULL), "bad")
    sk2 <- read_key("../keys/id_ecdsa384.pw", password = "test")
    expect_equal(sk1, sk2)
  }
  sk3 <- read_key("../keys/id_ecdsa384.openssh")
  sk4 <- read_key("../keys/id_ecdsa384.openssh.pw", password = "test")
  expect_equal(sk1, sk3)
  expect_equal(sk1, sk4)
})

test_that("reading public key formats", {
  pk2 <- read_pubkey("../keys/id_ecdsa384.pem")
  pk3 <- read_pubkey("../keys/id_ecdsa384.pub")
  pk4 <- read_pubkey("../keys/id_ecdsa384.sshpub")
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
  expect_equal(fp, "2378e98f946fbe07c28308835f932834a374a215ae515f65b77678613e412101")
})

test_that("SHA1 signatures", {
  skip_on_redhat()
  msg <- readBin("../keys/message", raw(), 100)
  sig <- readBin("../keys/message.sig.ecdsa384.sha1", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha1, pk1))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))

  sig <- signature_create(msg, sha1, sk1)
  expect_true(signature_verify(msg, sig, sha1, pk1))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))
})

test_that("SHA56 signatures", {
  msg <- readBin("../keys/message", raw(), 100)
  sig <- readBin("../keys/message.sig.ecdsa384.sha256", raw(), 1000)
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
  sig <- signature_create("../keys/message", sha256, "../keys/id_ecdsa384")
  writeBin(sig, tmp <- tempfile())
  expect_true(signature_verify("../keys/message", tmp, sha256, "../keys/id_ecdsa384.pub"))
  expect_equal(names(ecdsa_parse(sig)), c("r", "s"))
})

test_that("ec_keygen works", {
  key <- ec_keygen("P-384")
  expect_equal(as.list(key)$size, 384)
  expect_equal(as.list(key)$data$curve, "P-384")
  rm(key)
})

# Cleanup
rm(sk1, pk1)

} else {
  cat("ec not supported")
}
