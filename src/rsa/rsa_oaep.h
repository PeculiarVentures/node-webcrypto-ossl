#ifndef OSSL_RSA_OAEP_H_INCLUDE
#define OSSL_RSA_OAEP_H_INCLUDE

#include "common.h"

Handle<ScopedBIO> RSA_OAEP_enc_dec(
	Handle<ScopedEVP_PKEY> hKey,
	const EVP_MD *md,
	Handle<ScopedBIO> hData,
	Handle<ScopedBIO> hLabel,
	bool decrypt
	);

#endif // OSSL_RSA_OAEP_H_INCLUDE