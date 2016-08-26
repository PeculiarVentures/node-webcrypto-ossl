#ifndef OSSL_RSA_PSS_H_INCLUDE
#define OSSL_RSA_PSS_H_INCLUDE

#include "../core/common.h"

Handle<std::string> RSA_PSS_sign(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, int saltLen, Handle<std::string> in);
bool RSA_PSS_verify(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, int saltLen, Handle<std::string> in, Handle<std::string> signature);

#endif // OSSL_RSA_PSS_H_INCLUDE