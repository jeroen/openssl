test_that("aes key wrap matches RFC 3394", {
  hex_to_raw <- function(x) as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
  kek128 <- hex_to_raw("000102030405060708090A0B0C0D0E0F")
  kek256 <- hex_to_raw("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
  key128 <- hex_to_raw("00112233445566778899AABBCCDDEEFF")
  key256 <- hex_to_raw("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
  wrapped1 <- hex_to_raw("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
  wrapped2 <- hex_to_raw("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
  expect_equal(aes_keywrap(key128, kek128), wrapped1)
  expect_equal(aes_keyunwrap(wrapped1, kek128), key128)
  expect_equal(aes_keywrap(key256, kek256), wrapped2)
  expect_equal(aes_keyunwrap(wrapped2, kek256), key256)

  tampered <- wrapped1
  tampered[1] <- xor(tampered[1], as.raw(1))
  expect_error(aes_keyunwrap(tampered, kek128), "unwrap failed")
  expect_error(aes_keyunwrap(wrapped1, rev(kek128)), "unwrap failed")
  expect_error(aes_keywrap(rand_bytes(12), kek128), "multiple of 8")
})
