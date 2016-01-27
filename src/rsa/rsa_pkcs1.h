#ifndef OSSL_RSA_PKCS1_H_INCLUDE
#define OSSL_RSA_PKCS1_H_INCLUDE

#include "../core/common.h"

Handle<ScopedBIO> RSA_PKCS1_sign(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in);
bool RSA_PKCS1_verify(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in, Handle<ScopedBIO> signature);

#endif // OSSL_RSA_PKCS1_H_INCLUDE