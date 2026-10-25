context("Test RSA-PSS formats")

# RSA-PSS is stochastic, so we can't compare signatures, but can still verify.

# Read secret key and public key
sk1 <- read_key("../keys/id_rsa")
pk1 <- read_pubkey("../keys/id_rsa.pub")
msg <- readBin("../keys/message", raw(), 100)

test_that("RSA-PSS with MD5", {
  sig <- readBin("../keys/message.sig.rsa-pss.md5", raw(), 1000)

  # md5 signatures blocked by FIPS
  skip_if(fips_mode())
  expect_true(signature_verify(msg, sig, md5, pk1, pad = "pss"))
  expect_true(signature_verify(msg,
                               signature_create(msg, md5, sk1, pad = "pss"),
                               md5, pk1, pad = "pss"))
})

test_that("RSA-PSS with SHA1", {
  sig <- readBin("../keys/message.sig.rsa-pss.sha1", raw(), 1000)

  # sha1 signatures blocked by FIPS and Redhat
  skip_on_redhat()
  skip_if(fips_mode())
  expect_true(signature_verify(msg, sig, sha1, pk1, pad = "pss"))
  expect_true(signature_verify(msg,
                               signature_create(msg, sha1, sk1, pad = "pss"),
                               sha1, pk1, pad = "pss"))
})

test_that("RSA-PSS with SHA256", {
  sig <- readBin("../keys/message.sig.rsa-pss.sha256", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha256, pk1, pad = "pss"))
  expect_true(signature_verify(msg,
                               signature_create(msg, sha256, sk1, pad = "pss"),
                               sha256, pk1, pad = "pss"))

  sig <- readBin("../keys/message.sig.rsa-pss.sha256.salt32", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha256, pk1,
                               pad = "pss", salt_length = 32))
  # Can also verify with default "auto" salt length
  expect_true(signature_verify(msg, sig, sha256, pk1, pad = "pss"))
  # But not with wrong salt length
  expect_false(signature_verify(msg, sig, sha256, pk1,
                                pad = "pss", salt_length = 64))

  sig <- signature_create(msg, sha256, sk1, pad = "pss", salt_length = 32)
  expect_true(signature_verify(msg, sig, sha256, pk1,
                               pad = "pss", salt_length = 32))
  # Can also verify with default "auto" salt length
  expect_true(signature_verify(msg, sig, sha256, pk1, pad = "pss"))
  # But not with wrong salt length
  expect_false(signature_verify(msg, sig, sha256, pk1, salt_length = 64))

  sig <- readBin("../keys/message.sig.rsa-pss.sha256.saltdig", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha256, pk1, pad = "pss", "digest"))
  # Can also verify with default "auto" salt length
  expect_true(signature_verify(msg, sig, sha256, pk1, pad = "pss"))
  # But not with wrong salt length
  expect_false(signature_verify(msg, sig, sha256, pk1,
                                pad = "pss", salt_length = 64))

  sig <- signature_create(msg, sha256, sk1,
                          pad = "pss", salt_length = "digest")
  expect_true(signature_verify(msg, sig, sha256, pk1,
                               pad = "pss", salt_length = "digest"))
  # Can also verify with default "auto" salt length
  expect_true(signature_verify(msg, sig, sha256, pk1, pad = "pss"))
  # But not with wrong salt length
  expect_false(signature_verify(msg, sig, sha256, pk1,
                                pad = "pss", salt_length = 64))

  sig <- readBin("../keys/message.sig.rsa-pss.sha256.saltmax", raw(), 1000)
  expect_true(signature_verify(msg, sig, sha256, pk1, pad = "pss", "max"))
  # Can also verify with default "auto" salt length
  expect_true(signature_verify(msg, sig, sha256, pk1, pad = "pss"))
  # But not with wrong salt length
  expect_false(signature_verify(msg, sig, sha256, pk1,
                                pad = "pss", salt_length = 64))

  sig <- signature_create(msg, sha256, sk1, pad = "pss", salt_length = "max")
  expect_true(signature_verify(msg, sig, sha256, pk1,
                               pad = "pss", salt_length = "max"))
  # Can also verify with default "auto" salt length
  expect_true(signature_verify(msg, sig, sha256, pk1, pad = "pss"))
  # But not with wrong salt length
  expect_false(signature_verify(msg, sig, sha256, pk1,
                                pad = "pss", salt_length = 64))
})

# Cleanup
rm(sk1, pk1, msg)
