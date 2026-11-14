test_that("aes-gcm verifies the authentication tag", {
  key <- rand_bytes(32)
  x <- charToRaw("hello world")
  enc <- aes_gcm_encrypt(x, key)
  expect_length(attr(enc, "tag"), 16)
  expect_equal(aes_gcm_decrypt(enc, key), x)

  tampered <- enc
  tampered[1] <- xor(tampered[1], as.raw(1))
  expect_error(aes_gcm_decrypt(tampered, key), "authentication failed")

  badtag <- enc
  attr(badtag, "tag")[1] <- xor(attr(badtag, "tag")[1], as.raw(1))
  expect_error(aes_gcm_decrypt(badtag, key), "authentication failed")

  expect_warning(out <- aes_gcm_decrypt(enc, key, tag = NULL), "without verification")
  expect_equal(out, x)
})
