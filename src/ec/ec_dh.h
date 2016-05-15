#ifndef OSSL_EC_DH_H_INCLUDE
#define OSSL_EC_DH_H_INCLUDE

#include "../core/common.h"

Handle<std::string> ECDH_derive_key(Handle<ScopedEVP_PKEY> pkey, Handle<ScopedEVP_PKEY> pubkey, size_t &secret_len);
Handle<std::string> ECDH_derive_bits(Handle<ScopedEVP_PKEY> pubkey, Handle<ScopedEVP_PKEY> pkey, bool has_optional_length_bits, unsigned int optional_length_bits);

#endif // OSSL_EC_DH_H_INCLUDE