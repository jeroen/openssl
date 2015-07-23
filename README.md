Bindings to OpenSSL
-------------------

[![Build Status](https://travis-ci.org/jeroenooms/openssl.svg?branch=master)](https://travis-ci.org/jeroenooms/openssl)
![downloads](http://cranlogs.r-pkg.org/badges/grand-total/urltools)

OpenSSL bindings for R. Includes support for cryptographic hashing, secure RNG, encryption and
creating/verifying signatures. For more information, see the vignettes:

 - [random number generation](https://github.com/jeroenooms/openssl/blob/master/vignettes/secure_rng.Rmd) 
 - [hashing](https://github.com/jeroenooms/openssl/blob/master/vignettes/crypto_hashing.Rmd)

## Installation

Install from stable version from [CRAN](http://cran.r-project.org/web/packages/openssl/index.html):

```r
install.packages('openssl')
```

Or get the bleeding edge:

```r
library(devtools)
install_github("jeroenooms/openssl")
```
