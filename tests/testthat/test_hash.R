context("Test AES encryption")

test_that("AES-128 encrypts and decrypts for all lengths", {
  key <- md5(charToRaw("supersecret"))
  for(n in 0:100){
    x <- rand_bytes(n)
    y <- aes_cbc_encrypt(x, key)
    x2 <- aes_cbc_decrypt(y, key)
    expect_identical(x, x2)
  }
})

test_that("AES-256 encrypts and decrypts for all lengths", {
  key <- sha256(charToRaw("supersecret"))
  for(n in 0:100){
    x <- rand_bytes(n)
    y <- aes_cbc_encrypt(x, key)
    x2 <- aes_cbc_decrypt(y, key)
    expect_equal(x, x2)
  }
})

