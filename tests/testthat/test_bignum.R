context("Bignum")

test_that("Basic bignum math", {
  # Regular numbers
  x1 <- 123
  y1 <- 456

  # Bignum numbers
  x2 <- bignum(123)
  y2 <- bignum(456)

  expect_true(x1 == x2)
  expect_true(y1 == y2)
  expect_true(x2 != y2)
  expect_true(x2 < y2)
  expect_true(x2 <= y2)
  expect_false(x2 > y2)
  expect_false(x2 >= y2)
  expect_false(x1 == y2)
  expect_true(x1+y1 == x2+y2)
  expect_true(y1-x1 == y2-x2)
  expect_true(x1*y1 == x2*y2)
  expect_true(y2-y2 == 0)
  expect_true(y2 %% x2 == y1 %% x1)
  expect_true(y2 %/% x2 == y1 %/% x1)
  expect_true(x2 %% y2 == x1 %% y1)
  expect_error(x2-y2, "")
  expect_error(x2/y2, "integer")
})

test_that("Bignum arithmetic", {
  x <- bignum(123L)
  y <- bignum("123456789123456789")
  z <- bignum("D41D8CD98F00B204E9800998ECF8427E", hex = TRUE)

  # Basic arithmetic
  div <- z %/% y
  mod <- z %% y
  z2 <- div * y + mod
  expect_equal(z2, z)
  expect_true(div < z)
})
