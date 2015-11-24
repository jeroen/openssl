Bindings to OpenSSL
-------------------

[![Build Status](https://travis-ci.org/jeroenooms/openssl.svg?branch=master)](https://travis-ci.org/jeroenooms/openssl)
![downloads](http://cranlogs.r-pkg.org/badges/grand-total/openssl)

Bindings to OpenSSL libssl and libcrypto, plus custom SSH pubkey parsers.
Supports RSA, DSA and NIST curves P-256, P-384 and P-521. Cryptographic signatures
can either be created and verified manually or via x509 certificates. AES block
cipher is used in CBC mode for symmetric encryption; RSA for asymmetric (public key)
encryption. High-level envelope functions combine RSA and AES for encrypting arbitrary
sized data. Other utilities include key generators, hash functions (md5, sha1, sha256,
etc), base64 encoder, a secure random number generator, and 'bignum' math methods for
manually performing crypto calculations on large multibyte integers.

Vignettes:

 - [Generating Secure Random Numbers in R](https://cran.r-project.org/web/packages/openssl/vignettes/secure_rng.html) 
 - [Cryptographic Hashing in R](https://cran.r-project.org/web/packages/openssl/vignettes/crypto_hashing.html)

### Installation

Windows and Mac users can use the binary packages from [CRAN](http://cran.r-project.org/web/packages/openssl/index.html):

```r
install.packages("openssl")
```

To build the the development version from source:

```r
library(devtools)
install_github("jeroenooms/openssl")
```

Building from source requires `libssl` e.g:

 - deb: libssl-dev (Debian, Ubuntu)
 - rpm: openssl-devel (Fedora, Redhat)
 - brew: openssl (OSX)

Special note for Mac: because OSX includes an old version of openssl, brew does
not automatically link openssl. You need:

```
brew update
brew install openssl
brew link --force openssl
```

To check which version you are running (run in a fresh terminal):

```
openssl version -a
```

