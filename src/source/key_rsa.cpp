#include "key_rsa.h"

#define JWK_KTY_RSA "RSA"

#define JWK_ATTR_KTY "kty"
#define JWK_ATTR_N "n"
#define JWK_ATTR_E "e"
#define JWK_ATTR_D "d"
#define JWK_ATTR_P "p"
#define JWK_ATTR_Q "q"
#define JWK_ATTR_DP "dp"
#define JWK_ATTR_DQ "dq"
#define JWK_ATTR_QI "qi"

#define RSA_set_BN(v8Obj, v8Param, RsaKey, RsaKeyParam) \
	unsigned char* v8Param = (unsigned char*)node::Buffer::Data(Nan::Get(v8Obj, Nan::New(#v8Param).ToLocalChecked()).ToLocalChecked()->ToObject()); \
	RsaKey->RsaKeyParam = BN_bin2bn(v8Param, node::Buffer::Length(Nan::Get(v8Obj, Nan::New(#v8Param).ToLocalChecked()).ToLocalChecked()->ToObject()), RsaKey->RsaKeyParam);

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

v8::Local<v8::Object> RSA_export_jwk(EVP_PKEY *pkey, int &key_type) {
	LOG_FUNC();

	Nan::HandleScope();

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
	v8::Local<v8::Object> v8Jwk = Nan::New<v8::Object>();

	RSA *rsa = pkey->pkey.rsa;

	LOG_INFO("Convert RSA to JWK");
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_KTY).ToLocalChecked(), Nan::New(JWK_KTY_RSA).ToLocalChecked());
	LOG_INFO("Get RSA public key");
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_N).ToLocalChecked(), bn2buf(rsa->n));
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_E).ToLocalChecked(), bn2buf(rsa->e));
	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("Get RSA private key");
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_D).ToLocalChecked(), bn2buf(rsa->d));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_P).ToLocalChecked(), bn2buf(rsa->p));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_Q).ToLocalChecked(), bn2buf(rsa->q));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_DP).ToLocalChecked(), bn2buf(rsa->dmp1));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_DQ).ToLocalChecked(), bn2buf(rsa->dmq1));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_QI).ToLocalChecked(), bn2buf(rsa->iqmp));
	}

	return v8Jwk;
}

Handle<ScopedEVP_PKEY> RSA_import_jwk(v8::Local<v8::Object> v8Jwk, int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	v8::String::Utf8Value v8JwkKty(Nan::Get(v8Jwk, Nan::New(JWK_ATTR_KTY).ToLocalChecked()).ToLocalChecked()->ToString());

	if (strcmp(*v8JwkKty, "RSA") != 0) {
		THROW_ERROR("JWK key is not RSA");
	}

	RSA* rsa_key = RSA_new();

	LOG_INFO("set public key");
	RSA_set_BN(v8Jwk, n, rsa_key, n);
	RSA_set_BN(v8Jwk, e, rsa_key, e);

	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("set private key");
		RSA_set_BN(v8Jwk, d, rsa_key, d);
		RSA_set_BN(v8Jwk, p, rsa_key, p);
		RSA_set_BN(v8Jwk, q, rsa_key, q);
		RSA_set_BN(v8Jwk, dp, rsa_key, dmp1);
		RSA_set_BN(v8Jwk, dq, rsa_key, dmq1);
		RSA_set_BN(v8Jwk, qi, rsa_key, iqmp);
	}

	LOG_INFO("set key");

	ScopedEVP_PKEY pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey.Get(), rsa_key);

	return Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(pkey));
}