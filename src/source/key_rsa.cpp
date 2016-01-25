#include "key_rsa.h"

JWK_RSA* JWK_RSA_new() {
	return new JWK_RSA;
}
void JWK_RSA_free(JWK_RSA *jwk) {
	delete jwk;
};

ScopedSSL_free(JWK_RSA, JWK_RSA_free);

Handle<ScopedEVP_PKEY> RSA_generate(int modulus, int publicExponent) {
	LOG_FUNC();

	ScopedEVP_PKEY pkey = EVP_PKEY_new();
	RSA *rsa = NULL;
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
		THROW_ERROR("Unsuported publicExponent value");
	}

	bne = BN_new();
	if (BN_set_word(bne.Get(), e) != 1) {
		THROW_OPENSSL("RSA: E -> BIGNUM");
	}

	rsa = RSA_new();

	if (RSA_generate_key_ex(rsa, modulus, bne.Get(), NULL) != 1) {
		RSA_free(rsa);
		THROW_OPENSSL("RSA_generate_key_ex");
	}

	if (EVP_PKEY_assign_RSA(pkey.Get(), rsa) != 1) {
		RSA_free(rsa);
		THROW_OPENSSL("EVP_PKEY_assign_RSA");
	}

	return Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(pkey));
}

Handle<ScopedJWK_RSA> RSA_export_jwk(EVP_PKEY *pkey, int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	LOG_INFO("Check pkey");
	if (pkey == NULL) {
		THROW_ERROR("Key value is NULL");
	}
	if (pkey->type != EVP_PKEY_RSA) {
		THROW_ERROR("Key is not RSA type");
	}

	LOG_INFO("Create JWK Object");
	JWK_RSA* jwk = JWK_RSA_new();
	Handle<ScopedJWK_RSA> hJwk(new ScopedJWK_RSA(jwk));

	RSA *rsa = pkey->pkey.rsa;

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

	return hJwk;
}

Handle<ScopedEVP_PKEY> RSA_import_jwk(Handle<ScopedJWK_RSA> hJwk, int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	if (strcmp(hJwk->Get()->kty, "RSA") != 0) {
		THROW_ERROR("JWK key is not RSA");
	}

	RSA* rsa_key = RSA_new();

	LOG_INFO("set public key");
	rsa_key->n = BN_dup(hJwk->Get()->n.Get());
	rsa_key->e = BN_dup(hJwk->Get()->e.Get());

	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("set private key");
		rsa_key->d = BN_dup(hJwk->Get()->d.Get());
		rsa_key->p = BN_dup(hJwk->Get()->p.Get());
		rsa_key->q = BN_dup(hJwk->Get()->q.Get());
		rsa_key->dmp1 = BN_dup(hJwk->Get()->dp.Get());
		rsa_key->dmq1 = BN_dup(hJwk->Get()->dq.Get());
		rsa_key->iqmp = BN_dup(hJwk->Get()->qi.Get());
	}

	LOG_INFO("set key");
	ScopedEVP_PKEY pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey.Get(), rsa_key);

	return Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(pkey));
}