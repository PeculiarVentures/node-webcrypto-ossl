#ifndef OSSL_EC_DSA_H_INCLUDE
#define OSSL_EC_DSA_H_INCLUDE

#include "../core/common.h"

Handle<ScopedBIO> EC_DSA_sign(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in);
bool EC_DSA_verify(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in, Handle<ScopedBIO> signature);

#endif // OSSL_EC_DSA_H_INCLUDE