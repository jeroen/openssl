context("Sodium Compatibility")

test_that("Signatures are compatible with sodium", {
  skip_if(fips_mode())
  skip_if_not(openssl_config()$x25519)

  # Generate keypair with sodium
  sk <- sodium::sig_keygen()
  pk <- sodium::sig_pubkey(sk)
  msg <- serialize(iris, NULL)

  # Parse in openssl
  key <- read_ed25519_key(sk)
  pubkey <- read_ed25519_pubkey(pk)

  # Create sodium signature
  sig1 <- sodium::sig_sign(msg, key = sk)
  expect_true(sodium::sig_verify(msg, sig1, pk))
  expect_true(ed25519_verify(msg, sig1, pubkey = pubkey))

  # Create openssl signature
  sig2 <- ed25519_sign(msg, key)
  expect_true(sodium::sig_verify(msg, sig2, pk))
  expect_true(ed25519_verify(msg, sig2, pubkey = pubkey))

})

test_that("Diffie Hellman is compatible with sodium", {
  skip_if(fips_mode())
  skip_if_not(openssl_config()$x25519)
  # Generate keypair with sodium
  sk1 <- sodium::keygen()
  sk2 <- sodium::keygen()
  dh1 <- sodium::diffie_hellman(sk1, sodium::pubkey(sk2))

  # Same in openssl
  key <- read_x25519_key(sk2)
  pubkey <- read_x25519_pubkey(sodium::pubkey(sk1))
  dh2 <- x25519_diffie_hellman(key, pubkey)
  expect_equal(dh1, dh2)
})
