#include "key_exp.h"

#include "excep.h"

static Handle<std::string> KEY_export(EVP_PKEY *pkey, int(*i2d_function_bio)(BIO *bp, EVP_PKEY *key)) {
	LOG_FUNC();

	ScopedBIO out(BIO_new(BIO_s_mem()));

	if (i2d_function_bio(out.Get(), pkey) <= 0) {
		THROW_OPENSSL("Can not write key to BIO");
	}

	char *data;
	size_t datalen = BIO_get_mem_data(out.Get(), &data);
	Handle<std::string> hOutput(new std::string(data, datalen));

	return hOutput;
}

static Handle<ScopedEVP_PKEY> KEY_import(BIO *in, EVP_PKEY *(*d2i_function_bio)(BIO *bp, EVP_PKEY **a)) {
	LOG_FUNC();

	ScopedEVP_PKEY pkey;

	if (BIO_seek(in, 0) == -1){
		THROW_OPENSSL("BIO_seek");	
	}

	pkey = d2i_function_bio(in, nullptr);
	if (pkey.isEmpty()) {
		THROW_OPENSSL("Can not read key from BIO");
	}

	return Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(pkey));
}

Handle<std::string> KEY_export_spki(EVP_PKEY *pkey) {
	LOG_FUNC();

	return KEY_export(pkey, &i2d_PUBKEY_bio);
}

Handle<ScopedEVP_PKEY> KEY_import_spki(Handle<std::string> in) {
	LOG_FUNC();

	ScopedBIO bio(BIO_new_mem_buf((void *)in->c_str(), (int)in->length()));
	return KEY_import(bio.Get(), &d2i_PUBKEY_bio);
}

Handle<std::string> KEY_export_pkcs8(EVP_PKEY *pkey) {
	LOG_FUNC();

	return KEY_export(pkey, &i2d_PKCS8PrivateKeyInfo_bio);
}

Handle<ScopedEVP_PKEY> KEY_import_pkcs8(Handle<std::string> in) {
	LOG_FUNC();

	ScopedBIO bio(BIO_new_mem_buf((void *)in->c_str(), (int)in->length()));
	return KEY_import(bio.Get(), &d2i_PrivateKey_bio);
}