#include "../core/common.h"

Handle<ScopedEVP_PKEY> RSA_generate(int modulus, int publicExponent) {
	LOG_FUNC();

	ScopedEVP_PKEY pkey(EVP_PKEY_new());
	RSA *rsa = nullptr;
	unsigned long e = RSA_3;
	ScopedBIGNUM bne;


	switch (publicExponent) {
	case 0:
		e = RSA_3;
		break;
	case 1:
		e = RSA_F4;
		break;
	default:
		THROW_ERROR("Unsupported publicExponent value");
	}

	bne = BN_new();
	if (BN_set_word(bne.Get(), e) != 1) {
		THROW_OPENSSL("RSA: E -> BIGNUM");
	}

	rsa = RSA_new();

	if (RSA_generate_key_ex(rsa, modulus, bne.Get(), nullptr) != 1) {
		RSA_free(rsa);
		THROW_OPENSSL("RSA_generate_key_ex");
	}

	if (EVP_PKEY_assign_RSA(pkey.Get(), rsa) != 1) {
		RSA_free(rsa);
		THROW_OPENSSL("EVP_PKEY_assign_RSA");
	}

	return Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(pkey));
}