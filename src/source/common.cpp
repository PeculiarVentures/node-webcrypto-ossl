#include "common.h"

#include <openssl/x509.h>

v8::Local<v8::Object> bn2buf(BIGNUM* bn) {
	LOG_FUNC();

	int n = BN_num_bytes(bn);

	v8::Local<v8::Object> v8Buf = Nan::NewBuffer(n).ToLocalChecked();
	unsigned char* buf = (unsigned char*)node::Buffer::Data(v8Buf);
	if (!BN_bn2bin(bn, buf)) {
		THROW_OPENSSL("BN_bn2bin");
	}

	return v8Buf;
}

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

Handle<ScopedBIO> v8Buffer_to_ScopedBIO(v8::Local<v8::Value> v8Buffer) {
	LOG_FUNC();
	return v8Buffer_to_ScopedBIO(v8Buffer->ToObject());
}

Handle<ScopedBIO> v8Buffer_to_ScopedBIO(v8::Local<v8::Object> v8Buffer) {
	LOG_FUNC();

	LOG_INFO("Copy buffer to Bio");
	char *buf = node::Buffer::Data(v8Buffer);
	int buflen = node::Buffer::Length(v8Buffer);

	char* data = (char*)OPENSSL_malloc(buflen);
	memcpy(data, buf, buflen);

	BIO *in = BIO_new_mem_buf(data, buflen);
	BIO_set_flags(in, BIO_CLOSE);
	Handle<ScopedBIO> hBio(new ScopedBIO(in));

	return hBio;
}

v8::Local<v8::Object> ScopedBIO_to_v8Buffer(Handle<ScopedBIO> bio) {
	LOG_FUNC();

	LOG_INFO("Copy bio to buffer");
	char *data;
	int datalen = BIO_get_mem_data(bio->Get(), &data);

	v8::Local<v8::Object> v8Buffer = Nan::NewBuffer(datalen).ToLocalChecked();
	char *buffer = node::Buffer::Data(v8Buffer);
	memcpy(buffer, data, datalen);

	return v8Buffer;
}