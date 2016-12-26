#ifndef OSSL_PBKDF2_H_INCLUDE
#define OSSL_PBKDF2_H_INCLUDE

#include "../core/common.h"

#define EVP_PKEY_PBKDF2 NID_id_pbkdf2

class ScopedPbkdf2 {
public:
	ScopedPbkdf2() : type(EVP_PKEY_PBKDF2) {}
	ScopedPbkdf2(Handle<std::string> value) : value(value), type(EVP_PKEY_PBKDF2) {}
	~ScopedPbkdf2() {}

	Handle<std::string> value;

	Handle<std::string> deriveBits(Handle<std::string> salt, size_t iterations, const EVP_MD *md, size_t derived_bits_length);

	int type;
};

#endif // OSSL_PBKDF2_H_INCLUDE