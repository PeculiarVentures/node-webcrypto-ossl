#ifndef OSSL_EC_DSA_H_INCLUDE
#define OSSL_EC_DSA_H_INCLUDE

#include "../core/common.h"

Handle<std::string> EC_DSA_sign(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<std::string> in);
bool EC_DSA_verify(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<std::string> in, Handle<std::string> signature);

#endif // OSSL_EC_DSA_H_INCLUDE