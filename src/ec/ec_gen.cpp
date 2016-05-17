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

	/**
	 * Current flag is needed to get a CHROME like pkcs8, spki output
	 */
	EC_GROUP *group = (EC_GROUP *)EC_KEY_get0_group(eckey.Get());
	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

	pkey = Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(EVP_PKEY_new()));

	if (EVP_PKEY_assign_EC_KEY(pkey->Get(), eckey.Get()) != 1) {
		THROW_OPENSSL("EVP_PKEY_assign_EC_KEY");
	}

	eckey.unref();

	return pkey;
}