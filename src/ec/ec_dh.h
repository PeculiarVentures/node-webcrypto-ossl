#ifndef OSSL_EC_DH_H_INCLUDE
#define OSSL_EC_DH_H_INCLUDE

#include "../core/common.h"

Handle<std::string> ECDH_derive_key(Handle<ScopedEVP_PKEY> pkey, Handle<ScopedEVP_PKEY> pubkey, size_t &secret_len);

#endif // OSSL_EC_DH_H_INCLUDE