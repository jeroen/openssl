context("Google SSL tests")

# Certificates from https://pki.goog/

test_that("google certs validate", {
  cert <- download_ssl_cert('good.r1demo.pki.goog')
  ca <- read_cert('https://pki.goog/gtsr1/GTSR1.crt')
  expect_true(cert_verify(cert, ca))

  cert <- download_ssl_cert('good.r2demo.pki.goog')
  ca <- read_cert('https://pki.goog/gtsr2/GTSR2.crt')
  expect_true(cert_verify(cert, ca))

  cert <- download_ssl_cert('good.r3demo.pki.goog')
  ca <- read_cert('https://pki.goog/gtsr3/GTSR3.crt')
  expect_true(cert_verify(cert, ca))

  cert <- download_ssl_cert('good.r4demo.pki.goog')
  ca <- read_cert('https://pki.goog/gtsr4/GTSR4.crt')
  expect_true(cert_verify(cert, ca))

  # Google messed up, server doesn't work
  #cert <- download_ssl_cert('2021.globalsign.com')
  #ca <- read_cert('https://pki.goog/gsr2/GSR2.crt')
  #expect_true(cert_verify(cert, ca))

  cert <- download_ssl_cert('2038r4.globalsign.com')
  ca <- read_cert('https://pki.goog/gsr4/GSR4.crt')
  expect_true(cert_verify(cert, ca))
})
