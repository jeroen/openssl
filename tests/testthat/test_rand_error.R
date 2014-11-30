context("Test the error handlers for rand_* functions")

test_that("rand_bytes detects non-numeric arguments", {

  expect_that(rand_bytes("turnip"), throws_error(regexp = "Please provide a numeric or integer value for n", fixed = TRUE))

})

test_that("pseudo_rand_bytes detects non-numeric arguments", {

  expect_that(pseudo_rand_bytes("turnip"), throws_error(regexp = "Please provide a numeric or integer value for n", fixed = TRUE))

})
