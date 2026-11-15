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

test_that("aes-gcm authenticates additional data", {
  hex_to_raw <- function(x) as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
  key <- hex_to_raw("feffe9928665731c6d6a8f9467308308")
  iv <- hex_to_raw("cafebabefacedbaddecaf888")
  aad <- hex_to_raw("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  pt <- hex_to_raw("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
  ct <- hex_to_raw("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
  tag <- hex_to_raw("5bc94fbc3221a5db94fae95ae7121a47")
  enc <- aes_gcm_encrypt(pt, key, iv = iv, aad = aad)
  expect_equal(as.vector(enc), ct)
  expect_equal(attr(enc, "tag"), tag)
  expect_equal(aes_gcm_decrypt(enc, key, aad = aad), pt)
  expect_error(aes_gcm_decrypt(enc, key), "authentication failed")
  expect_error(aes_gcm_decrypt(enc, key, aad = rev(aad)), "authentication failed")

  enc <- aes_gcm_encrypt(charToRaw("hello"), key, aad = "header")
  expect_equal(aes_gcm_decrypt(enc, key, aad = charToRaw("header")), charToRaw("hello"))
})
