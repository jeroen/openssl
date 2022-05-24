context("Google SSL tests")

# Certificates from https://pki.goog/

test_that("google certs validate", {
  # CRAN checks have to work offline
  skip_on_cran()

  # Google CA root certs
  gsr4 <- read_cert('https://pki.goog/repo/certs/gsr4.der', der = TRUE)
  gtsr1 <- read_cert('https://pki.goog/repo/certs/gtsr1.der', der = TRUE)
  gtsr2 <- read_cert('https://pki.goog/repo/certs/gtsr2.der', der = TRUE)
  gtsr3 <- read_cert('https://pki.goog/repo/certs/gtsr3.der', der = TRUE)
  gtsr4 <- read_cert('https://pki.goog/repo/certs/gtsr4.der', der = TRUE)

  # Test good servers
  expect_true(cert_verify(download_ssl_cert('good.gsr4demo.pki.goog'), gsr4))
  expect_true(cert_verify(download_ssl_cert('good.r1demo.pki.goog'), gtsr1))
  expect_true(cert_verify(download_ssl_cert('good.r2demo.pki.goog'), gtsr2))
  expect_true(cert_verify(download_ssl_cert('good.r3demo.pki.goog'), gtsr3))
  expect_true(cert_verify(download_ssl_cert('good.r4demo.pki.goog'), gtsr4))

  # Test expired servers
  expect_error(cert_verify(download_ssl_cert('expired.gsr4demo.pki.goog'), gsr4), 'expired')
  expect_error(cert_verify(download_ssl_cert('expired.r1demo.pki.goog'), gtsr1), 'expired')
  expect_error(cert_verify(download_ssl_cert('expired.r2demo.pki.goog'), gtsr2), 'expired')
  expect_error(cert_verify(download_ssl_cert('expired.r3demo.pki.goog'), gtsr3), 'expired')
  expect_error(cert_verify(download_ssl_cert('expired.r4demo.pki.goog'), gtsr4), 'expired')
})
