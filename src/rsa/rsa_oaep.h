#ifndef OSSL_RSA_OAEP_H_INCLUDE
#define OSSL_RSA_OAEP_H_INCLUDE

#include "../core/common.h"

Handle<std::string> RSA_OAEP_enc_dec(
	Handle<ScopedEVP_PKEY> hKey,
	const EVP_MD *md,
	Handle<std::string> hData,
	Handle<std::string> hLabel,
	bool decrypt
	);

#endif // OSSL_RSA_OAEP_H_INCLUDE