context("Multihash")

test_that("Multihash for connections or raw vectors", {
  desc <- system.file('DESCRIPTION')
  buf <- readBin(desc, raw(), 1e5)
  algos <- c("sha1", "sha256", "sha512")
  out1 <- multihash(buf, algos = algos)
  out2 <- multihash(file(desc), algos = algos)
  expect_identical(out1, out2)
  expect_named(out1, algos)
  expect_equal(out1$sha1, sha1(file(desc)))
  expect_equal(out1$sha256, sha256(file(desc)))
  expect_equal(out1$sha512, sha512(file(desc)))
})

test_that("Multihash for text vectors", {
  algos <- c("sha1", "sha256", "sha512")
  out0 <- multihash(character(), algos = algos)
  expect_is(out0, 'data.frame')
  expect_named(out0, algos)
  expect_equal(nrow(out0), 0)

  out1 <- multihash("foo", algos = algos)
  expect_is(out1, 'data.frame')
  expect_named(out1, algos)
  expect_equal(nrow(out1), 1)

  out2 <- multihash(c("foo", "bar"), algos = algos)
  expect_is(out2, 'data.frame')
  expect_named(out2, algos)
  expect_equal(nrow(out2), 2)

  expect_equal(out2[1,], out1)

})
