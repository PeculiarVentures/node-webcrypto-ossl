#include "ec_jwk.h"

Handle<JwkEc> JwkEc::From(Handle<ScopedEVP_PKEY> pkey, int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	LOG_INFO("Check pkey");
	if (pkey == NULL) {
		THROW_ERROR("Key value is NULL");
	}
	if (pkey->Get()->type != EVP_PKEY_EC) {
		THROW_ERROR("Key is not EC type");
	}

	LOG_INFO("Create JWK Object");
	Handle<JwkEc> jwk(new JwkEc());

	EC_KEY *ec = NULL;
	const EC_POINT *point = NULL;

	ScopedBN_CTX ctx = NULL;
	const EC_GROUP *group = NULL;

	LOG_INFO("Convert EC to JWK");
	ec = pkey->Get()->pkey.ec;
	point = EC_KEY_get0_public_key(const_cast<const EC_KEY*>(ec));
	group = EC_KEY_get0_group(ec);
	ctx = BN_CTX_new();

	LOG_INFO("Get curve name");
	jwk->crv = EC_GROUP_get_curve_name(group);
	

	LOG_INFO("Get public key");
	jwk->x = BN_CTX_get(ctx.Get());
	jwk->y = BN_CTX_get(ctx.Get());
	if (!EC_POINT_get_affine_coordinates_GF2m(group, point, jwk->x.Get(), jwk->y.Get(), ctx.Get())) {
		THROW_OPENSSL("EC_POINT_get_affine_coordinates_GF2m");
	}

	if (key_type == NODESSL_KT_PRIVATE) {
		jwk->d = (BIGNUM*)EC_KEY_get0_private_key(const_cast<const EC_KEY*>(ec));
		if (jwk->d.isEmpty()) {
			THROW_OPENSSL("EC_KEY_get0_private_key");
		}
	}
	
	return jwk;
}

Handle<ScopedEVP_PKEY> JwkEc::To(int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	LOG_INFO("import EC from JWK");
	ScopedEC_KEY ec_key = EC_KEY_new();

	LOG_INFO("set public key");
	EC_GROUP *group = EC_GROUP_new_by_curve_name(this->crv);
	if (!group) {
		THROW_OPENSSL("EC_GROUP_new_by_curve_name");
	}

	EC_KEY_set_group(ec_key.Get(), group);

	if (EC_KEY_set_public_key_affine_coordinates(ec_key.Get(), this->x.Get(), this->y.Get()) != 1) {
		THROW_OPENSSL("EC_KEY_set_public_key_affine_coordinates");
	}
	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("set private key");

		if (EC_KEY_set_private_key(ec_key.Get(), this->d.Get()) != 1) {
			THROW_OPENSSL("EC_KEY_set_private_key");
		}
	}

	LOG_INFO("set internal key");
	Handle<ScopedEVP_PKEY> new_key(new ScopedEVP_PKEY(EVP_PKEY_new()));
	EVP_PKEY_assign_EC_KEY(new_key->Get(), ec_key.Get());
	ec_key.unref();
	
	return new_key;
}