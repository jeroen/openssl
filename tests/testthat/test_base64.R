test_that("base64 roundtrips", {
  for(n in c(0:10, 47:49, 63:66, 1000, 100000)){
    x <- as.raw(sample(0:255, n, TRUE))
    expect_identical(base64_decode(base64_encode(x)), x)
    expect_identical(base64_decode(base64_encode(x, linebreaks = TRUE)), x)
  }
  expect_identical(base64_encode(charToRaw("foobar")), "Zm9vYmFy")
  expect_identical(base64_encode(as.raw(1:50), linebreaks = TRUE),
    "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8w\nMTI=\n")
  expect_identical(base64_decode(" Zm9v\tYmFy\n"), charToRaw("foobar"))
  expect_identical(base64_decode("Zm9vYmE="), charToRaw("fooba"))
  expect_identical(base64_decode(""), raw(0))
})

test_that("base64 errors on invalid input", {
  expect_error(base64_decode("Zm9vYg"), "base64")
  expect_error(base64_decode("!!!!"), "base64")
  expect_error(base64_decode("Zm9v=YmFy"), "base64")
  expect_error(base64_decode("Zm9vYmFy===="), "base64")
})
