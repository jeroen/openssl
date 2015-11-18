#' Toolkit for Encryption, Signatures and Certificates based on OpenSSL
#'
#' Bindings to OpenSSL libssl and libcrypto, plus custom SSH \link[openssl:read_key]{pubkey}
#' parsers. Supports RSA, DSA and NIST curves P-256, P-384 and P-521. Cryptographic
#' \link[openssl:signature_verify]{signatures} can either be created and verified
#' manually or via x509 \link[openssl:cert_verify]{certificates}. The
#' \link[openssl:aes_cbc]{AES block cipher} is used in CBC mode for symmetric
#' encryption; RSA for \link[openssl:rsa_encrypt]{asymmetric (public key)}
#' encryption. High-level \link[openssl:encrypt_envelope]{envelope} methods
#' combine RSA and AES for encrypting arbitrary sized data. Other utilities include
#' \link[openssl:rsa_keygen]{key generators}, hash functions (\code{\link[openssl:md5]{md5}},
#' \code{\link[openssl:sha1]{sha1}}, \code{\link[openssl:sha256]{sha256}}, etc),
#' \code{\link[openssl:base64_encode]{base64}} encoder, a secure \link[openssl:rand_bytes]{random number generator},
#' and \code{\link[openssl:bignum]{bignum}} math methods for manually performing crypto
#' calculations on large multibyte integers.
#'@author Jeroen Ooms, Oliver Keyes
#'@docType package
#'@name openssl
#'@aliases openssl openssl-package
NULL
