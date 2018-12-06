#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>

#include "compatibility.h"

#ifndef HAS_OPENSSL11_API

int MY_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d){
  if(n) r->n = n;
  if(e) r->e = e;
  if(d) r->d = d;
  return 1;
}

int MY_RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q){
  if(p) r->p = p;
  if(q) r->q = q;
  return 1;
}

int MY_RSA_set0_crt_params(RSA *r,BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp){
  if(dmp1) r->dmp1 = dmp1;
  if(dmq1) r->dmq1 = dmq1;
  if(iqmp) r->iqmp = iqmp;
  return 1;
}

void MY_RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d){
  if(n) *n = r->n;
  if(e) *e = r->e;
  if(d) *d = r->d;
}

void MY_RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q){
  if(p) *p = r->p;
  if(q) *q = r->q;
}

void MY_RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp){
  if(dmp1) *dmp1 = r->dmp1;
  if(dmq1) *dmq1 = r->dmq1;
  if(iqmp) *iqmp = r->iqmp;
}

int MY_DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g){
  if(p) d->p = p;
  if(q) d->q = q;
  if(g) d->g = g;
  return 1;
}

int MY_DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key){
  if(pub_key) d->pub_key = pub_key;
  if(priv_key) d->priv_key = priv_key;
  return 1;
}

void MY_DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g){
  if(p) *p = d->p;
  if(q) *q = d->q;
  if(g) *g = d->g;
}

void MY_DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key){
  if(pub_key) *pub_key = d->pub_key;
  if(priv_key) *priv_key = d->priv_key;
}

void MY_X509_get0_signature(const ASN1_BIT_STRING **psig, const X509_ALGOR **palg, const X509 *x){
  if(psig) *psig = x->signature;
  if(palg) *palg = x->sig_alg;
}

void MY_ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps){
  if(pr) *pr = sig->r;
  if(ps) *ps = sig->s;
}

int MY_ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s){
  sig->r = r;
  sig->s = s;
  return 1;
}

#endif
