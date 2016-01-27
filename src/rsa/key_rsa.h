#ifndef OSSL_KEY_RSA_H_INCLUDE
#define OSSL_KEY_RSA_H_INCLUDE

#include "common.h"
#include "excep.h"

Handle<ScopedBIO> RSA_PKCS1_sign(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in);
bool RSA_PKCS1_verify(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in, Handle<ScopedBIO> signature);

#endif // OSSL_KEY_RSA_H_INCLUDE