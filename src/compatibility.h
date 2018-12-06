/* Compatibility stuff for API changes in OpenSSL 1.1 */
#include <openssl/opensslv.h>
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x2070000fL
#define HAS_OPENSSL11_API 1
#elif !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100001L
#define HAS_OPENSSL11_API 1
#endif

#ifdef HAS_OPENSSL11_API

#define MY_RSA_set0_key RSA_set0_key
#define MY_RSA_set0_factors RSA_set0_factors
#define MY_RSA_set0_crt_params RSA_set0_crt_params
#define MY_RSA_get0_key RSA_get0_key
#define MY_RSA_get0_factors RSA_get0_factors
#define MY_RSA_get0_crt_params RSA_get0_crt_params
#define MY_DSA_set0_pqg DSA_set0_pqg
#define MY_DSA_set0_key DSA_set0_key
#define MY_DSA_get0_pqg DSA_get0_pqg
#define MY_DSA_get0_key DSA_get0_key
#define MY_X509_get0_signature X509_get0_signature
#define MY_ECDSA_SIG_get0 ECDSA_SIG_get0
#define MY_ECDSA_SIG_set0 ECDSA_SIG_set0

#else

int MY_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int MY_RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int MY_RSA_set0_crt_params(RSA *r,BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
void MY_RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
void MY_RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void MY_RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp);
int MY_DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int MY_DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key);
void MY_DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
void MY_DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key);
void MY_X509_get0_signature(const ASN1_BIT_STRING **psig, const X509_ALGOR **palg, const X509 *x);
void MY_ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int MY_ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

#endif
