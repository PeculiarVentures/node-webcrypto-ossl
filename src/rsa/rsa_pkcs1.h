#ifndef OSSL_RSA_PKCS1_H_INCLUDE
#define OSSL_RSA_PKCS1_H_INCLUDE

#include "../core/common.h"

Handle<std::string> RSA_PKCS1_sign(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<std::string> in);
bool RSA_PKCS1_verify(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<std::string> in, Handle<std::string> signature);

#endif // OSSL_RSA_PKCS1_H_INCLUDE