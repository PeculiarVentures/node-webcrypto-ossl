#include "key_exp.h"

#include "excep.h"

static Handle<ScopedBIO> KEY_export(EVP_PKEY *pkey, int(*i2d_function_bio)(BIO *bp, EVP_PKEY *key)) {
	LOG_FUNC();

	ScopedBIO out = BIO_new(BIO_s_mem());

	if (i2d_function_bio(out.Get(), pkey) <= 0) {
		THROW_OPENSSL("Can not write key to BIO");
	}

	return Handle<ScopedBIO>(new ScopedBIO(out));
}

static Handle<ScopedEVP_PKEY> KEY_import(BIO *in, EVP_PKEY *(*d2i_function_bio)(BIO *bp, EVP_PKEY **a)) {
	LOG_FUNC();

	ScopedEVP_PKEY pkey;

	BIO_seek(in, 0);

	pkey = d2i_function_bio(in, NULL);
	if (pkey.isEmpty()) {
		THROW_OPENSSL("Can not read key from BIO");
	}

	return Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(pkey));
}

Handle<ScopedBIO> KEY_export_spki(EVP_PKEY *pkey) {
	LOG_FUNC();

	return KEY_export(pkey, &i2d_PUBKEY_bio);
}

Handle<ScopedEVP_PKEY> KEY_import_spki(BIO *in) {
	LOG_FUNC();

	return KEY_import(in, &d2i_PUBKEY_bio);
}

Handle<ScopedBIO> KEY_export_pkcs8(EVP_PKEY *pkey) {
	LOG_FUNC();

	return KEY_export(pkey, &i2d_PKCS8PrivateKeyInfo_bio);
}

Handle<ScopedEVP_PKEY> KEY_import_pkcs8(BIO *in) {
	LOG_FUNC();

	return KEY_import(in, &d2i_PrivateKey_bio);
}