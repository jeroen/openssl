test_that("ssl-ctx integration works", {
  skip_if_not_installed('curl')
  skip_if(packageVersion('curl') < '4.3.3')
  skip_if_not(ssl_ctx_curl_version_match())

  test <- download_ssl_cert('cran.r-project.org')[[1]]

  cb1 <- function(cert){
    identical(test, cert)
  }

  cb2 <- function(cert){
    #print("Rejecting cert...")
    FALSE
  }

  h1 <- curl::new_handle(forbid_reuse = TRUE, ssl_ctx_function = function(ssl_ctx){
    ssl_ctx_set_verify_callback(ssl_ctx, cb1)
  })
  req1 <- curl::curl_fetch_memory('https://cran.r-project.org', handle = h1)
  expect_equal(req1$status_code, 200)

  h2 <- curl::new_handle(forbid_reuse = TRUE, ssl_ctx_function = function(ssl_ctx){
    ssl_ctx_set_verify_callback(ssl_ctx, cb2)
  })

  expect_error(curl::curl_fetch_memory('https://cran.r-project.org', handle = h2), "certificate")
})
