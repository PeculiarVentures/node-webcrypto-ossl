#include "rsa_jwk.h"

Handle<JwkRsa> JwkRsa::From(Handle<ScopedEVP_PKEY> pkey, int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	LOG_INFO("Check pkey");
	if (pkey == nullptr) {
		THROW_ERROR("Key value is nullptr");
	}
	if (pkey->Get()->type!= EVP_PKEY_RSA) {
		THROW_ERROR("Key is not RSA type");
	}

	LOG_INFO("Create JWK Object");
	Handle<JwkRsa> jwk(new JwkRsa());

	RSA *rsa = pkey->Get()->pkey.rsa;

	LOG_INFO("Convert RSA to JWK");
	jwk->type = key_type;
	LOG_INFO("Get RSA public key");
	jwk->n = BN_dup(rsa->n);
	jwk->e = BN_dup(rsa->e);
	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("Get RSA private key");
		jwk->d = BN_dup(rsa->d);
		jwk->p = BN_dup(rsa->p);
		jwk->q = BN_dup(rsa->q);
		jwk->dp = BN_dup(rsa->dmp1);
		jwk->dq = BN_dup(rsa->dmq1);
		jwk->qi = BN_dup(rsa->iqmp);
	}

	return jwk;
}

Handle<ScopedEVP_PKEY> JwkRsa::To(int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	if (strcmp(this->kty, "RSA") != 0) {
		THROW_ERROR("JWK key is not RSA");
	}

	RSA* rsa_key = RSA_new();

	LOG_INFO("set public key");
	rsa_key->n = BN_dup(this->n.Get());
	rsa_key->e = BN_dup(this->e.Get());

	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("set private key");
		rsa_key->d = BN_dup(this->d.Get());
		rsa_key->p = BN_dup(this->p.Get());
		rsa_key->q = BN_dup(this->q.Get());
		rsa_key->dmp1 = BN_dup(this->dp.Get());
		rsa_key->dmq1 = BN_dup(this->dq.Get());
		rsa_key->iqmp = BN_dup(this->qi.Get());
	}

	LOG_INFO("set key");
	ScopedEVP_PKEY pkey(EVP_PKEY_new());
	EVP_PKEY_assign_RSA(pkey.Get(), rsa_key);

	return Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(pkey));
}