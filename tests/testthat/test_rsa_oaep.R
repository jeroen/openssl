test_that("rsa oaep supports custom hash", {
  key <- rsa_keygen()
  pubkey <- key$pubkey
  x <- rand_bytes(32)
  expect_equal(rsa_decrypt(rsa_encrypt(x, pubkey), key), x)
  expect_equal(rsa_decrypt(rsa_encrypt(x, pubkey, oaep = TRUE), key, oaep = TRUE), x)
  expect_equal(rsa_decrypt(rsa_encrypt(x, pubkey, oaep = TRUE), key, oaep = "sha1"), x)
  enc <- rsa_encrypt(x, pubkey, oaep = "sha256")
  expect_equal(rsa_decrypt(enc, key, oaep = "sha256"), x)
  expect_error(rsa_decrypt(enc, key, oaep = TRUE))
  expect_error(rsa_encrypt(x, pubkey, oaep = "foo"), "Invalid hash")
})
