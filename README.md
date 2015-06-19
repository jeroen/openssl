Bindings to OpenSSL
-------------------

[![Build Status](https://travis-ci.org/jeroenooms/openssl.svg?branch=master)](https://travis-ci.org/jeroenooms/openssl)
![downloads](http://cranlogs.r-pkg.org/badges/grand-total/urltools)

`openssl` provides an interface to the OpenSSL libraries. In doing so, it provides R users with cryptographically secure hashing
and random number generation functions that you can use to securely encrypt and anonymise data. For more information, see the vignettes on [random number generation](https://github.com/jeroenooms/openssl/blob/master/vignettes/secure_rng.Rmd) and [hashing](https://github.com/jeroenooms/openssl/blob/master/vignettes/crypto_hashing.Rmd).

## Installation

`openssl` can be installed [from CRAN](http://cran.r-project.org/web/packages/openssl/index.html) with `install.packages('openssl')`. If you're interested in getting the cutting edge version, instead run:

> devtools::install_github("jeroenooms/openssl")
