#include "ec_jwk.h"

Handle<JwkEc> JwkEc::From(Handle<ScopedEVP_PKEY> pkey, int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	LOG_INFO("Check pkey");
	if (pkey == nullptr) {
		THROW_ERROR("Key value is nullptr");
	}
	if (pkey->Get()->type != EVP_PKEY_EC) {
		THROW_ERROR("Key is not EC type");
	}

	LOG_INFO("Create JWK Object");
	Handle<JwkEc> jwk(new JwkEc());

	EC_KEY *ec = nullptr;
	const EC_POINT *point = nullptr;

	ScopedBN_CTX ctx(nullptr);
	const EC_GROUP *group = nullptr;

	LOG_INFO("Convert EC to JWK");
	ec = pkey->Get()->pkey.ec;

	point = EC_KEY_get0_public_key(const_cast<const EC_KEY*>(ec));
	group = EC_KEY_get0_group(ec);
	ctx = BN_CTX_new();

	LOG_INFO("Get curve name");
	jwk->crv = EC_GROUP_get_curve_name(group);

	ScopedBIGNUM x, y;
	x = BN_CTX_get(ctx.Get());
	y = BN_CTX_get(ctx.Get());

	LOG_INFO("Get public key");
	if (1 != EC_POINT_get_affine_coordinates_GFp(group, point, x.Get(), y.Get(), ctx.Get())) {
		THROW_OPENSSL("EC_POINT_get_affine_coordinates_GFp");
	}
	jwk->x = BN_dup(x.Get());
	jwk->y = BN_dup(y.Get());

	if (key_type == NODESSL_KT_PRIVATE) {
		const BIGNUM *d = EC_KEY_get0_private_key(const_cast<const EC_KEY*>(ec));
		jwk->d = BN_dup(d);
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
	ScopedEC_KEY ec_key(EC_KEY_new());

	LOG_INFO("set public key");
	ScopedEC_GROUP group(EC_GROUP_new_by_curve_name(this->crv));
	if (group.isEmpty()) {
		THROW_OPENSSL("EC_GROUP_new_by_curve_name");
	}

	EC_KEY_set_group(ec_key.Get(), group.Get());

	ScopedBIGNUM x(BN_dup(this->x.Get()));
	ScopedBIGNUM y(BN_dup(this->y.Get()));

	if (EC_KEY_set_public_key_affine_coordinates(ec_key.Get(), x.Get(), y.Get()) != 1) {
		THROW_OPENSSL("EC_KEY_set_public_key_affine_coordinates");
	}
	x.unref();
	y.unref();
	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("set private key");

		ScopedBIGNUM d(BN_dup(this->d.Get()));
		if (EC_KEY_set_private_key(ec_key.Get(), d.Get()) != 1) {
			THROW_OPENSSL("EC_KEY_set_private_key");
		}
		d.unref();
	}

	LOG_INFO("set internal key");
	Handle<ScopedEVP_PKEY> new_key(new ScopedEVP_PKEY(EVP_PKEY_new()));
	EVP_PKEY_assign_EC_KEY(new_key->Get(), ec_key.Get());
	ec_key.unref();

	return new_key;
}
