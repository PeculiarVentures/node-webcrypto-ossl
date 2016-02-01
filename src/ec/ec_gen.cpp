#include "ec_gen.h"

Handle<ScopedEVP_PKEY> EC_generate(int &nidEc) {
	LOG_FUNC();

	Handle<ScopedEVP_PKEY> pkey;

	ScopedEC_KEY eckey(EC_KEY_new_by_curve_name(nidEc));

	if (eckey.isEmpty()) {
		THROW_OPENSSL("EC_KEY_new_by_curve_name");
	}
	if (!EC_KEY_generate_key(eckey.Get())) {
		THROW_OPENSSL("EC_KEY_generate_key");
	}

	pkey = Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(EVP_PKEY_new()));

	if (EVP_PKEY_assign_EC_KEY(pkey->Get(), eckey.Get()) != 1) {
		THROW_OPENSSL("EVP_PKEY_assign_EC_KEY");
	}

	eckey.unref();

	return pkey;
}