#' Toolkit for Encryption, Signatures and Certificates based on OpenSSL
#'
#' Bindings to OpenSSL libssl and libcrypto, plus custom SSH [pubkey][openssl::read_key]
#' parsers. Supports RSA, DSA and NIST curves P-256, P-384 and P-521. Cryptographic
#' [signatures][openssl::signatures] can either be created and verified
#' manually or via x509 [certificates][openssl::certificates]. The
#' [AES block cipher][openssl::aes_cbc] is used in CBC mode for symmetric
#' encryption; RSA for [asymmetric (public key)][openssl::rsa_encrypt]
#' encryption. High-level [envelope][openssl::encrypt_envelope] methods
#' combine RSA and AES for encrypting arbitrary sized data. Other utilities include
#' [key generators][openssl::keygen], hash functions ([`md5()`][openssl::hash],
#' [`sha1()`][openssl::hash], [`sha256()`][openssl::hash], etc),
#' [`base64()`][openssl::base64_encode] encoder, a secure [random number generator][openssl::rand_bytes],
#' and [openssl::bignum()] math methods for manually performing crypto
#' calculations on large multibyte integers.
#'@author Jeroen Ooms, Oliver Keyes
#'@docType package
#'@name openssl
#'@aliases openssl openssl-package
NULL
