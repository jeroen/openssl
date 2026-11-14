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

test_that("aes-gcm is compatible with webcrypto", {
  hex_to_raw <- function(x) as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
  key <- hex_to_raw("ea35fb3d31100040c4e02109719b7d169f26879fdcf7c81ba179e37c0fb404fa")
  msg <- hex_to_raw("3a950241c87f2587de2e9970ffc6acd50d1b4cd8079d")
  ct <- msg[1:6]
  tag <- msg[7:22]
  expect_equal(aes_gcm_decrypt(ct, key, iv = raw(16), tag = tag), charToRaw("testje"))
  enc <- aes_gcm_encrypt(charToRaw("testje"), key, iv = raw(16))
  expect_equal(c(as.vector(enc), attr(enc, "tag")), msg)
})
