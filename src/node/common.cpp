#include "common.h"

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

	BIO_set_flags(bio->Get(), BIO_CLOSE);

	return v8Buffer;
}

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