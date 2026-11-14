context("FIPS mode")

test_that("printing works correctly under FIPS", {
  skip_if(!fips_mode())
  # Some print functions have a conditional check for fips_mode(). These tests
  # verify that those branches produce working output on FIPS systems.
  key <- openssl::rsa_keygen(2048L)
  cert <- read_cert("../certigo/example-root.crt")
  expect_output(print(key))
  expect_output(print(key$pubkey))
  expect_output(print(cert))
})

expect_md5_password <- function(file, password) {
  expect_error(
    read_key(file, password = password),
    # The error message varies by OpenSSL-FIPS version.
    "OpenSSL error in EVP_DigestInit_ex: disabled for (fips|FIPS)"
  )
}

test_that("keys with MD5-hashed passwords generate errors under FIPS", {
  skip_if(!fips_mode())
  expect_md5_password("../keys/id_dsa.pw", password = "test")
  if (openssl_config()$ec) {
    expect_md5_password("../keys/id_ecdsa.pw", password = "test")
    expect_md5_password("../keys/id_ecdsa384.pw", password = "test")
    expect_md5_password("../keys/id_ecdsa521.pw", password = "test")
  }
})

expect_unknown_cipher <- function(file, password = NULL) {
  expect_error(
    read_p12(file, password = password),
    # The error message varies by OpenSSL-FIPS version.
    "OpenSSL error in EVP_(PBE_CipherInit: unknown cipher|CipherInit_ex: disabled for FIPS)"
  )
}

test_that("p12 certificates with unsupported ciphers generate errors under FIPS", {
  skip_if(!fips_mode())
  expect_unknown_cipher("../google.dk/wildcard-google.dk-chain.p12")
  expect_unknown_cipher(
      "../google.dk/wildcard-google.dk-chain-password.p12",
      password = "password"
  )
  expect_unknown_cipher("../certigo/example-root.p12", password = "password")
  expect_unknown_cipher("../certigo/example-leaf.p12", password = "password")
  expect_unknown_cipher(
    "../certigo/example-elliptic-sha1.p12", password = "password"
  )
})

expect_invalid_key_size <- function(expr) {
  # The error message varies by OpenSSL version and algorithm.
  expect_error(expr, "(key size invalid|key too short|invalid key length|null)")
}

test_that("small keys cannot be generated under FIPS", {
  skip_if(!fips_mode())
  # Required on some Red Hat systems to actually enforce full key length
  # requirements.
  Sys.setenv("OPENSSL_ENFORCE_MODULUS_BITS" = "1")
  expect_invalid_key_size(rsa_keygen(512))
  expect_invalid_key_size(rsa_keygen(1024))
  expect_invalid_key_size(dsa_keygen(512))
  expect_invalid_key_size(dsa_keygen(1024))
})
