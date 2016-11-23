#include "common.h"

Handle<std::string> v8Buffer_to_String(v8::Local<v8::Value> v8Buffer) {
	LOG_FUNC();
	return v8Buffer_to_String(v8Buffer->ToObject());
}

Handle<std::string> v8Buffer_to_String(v8::Local<v8::Object> v8Buffer) {
	LOG_FUNC();

	LOG_INFO("Copy buffer to Bio");
	char *buf = node::Buffer::Data(v8Buffer);
	int buflen = (int)node::Buffer::Length(v8Buffer);

	Handle<std::string> hBuffer(new std::string(buf, buflen));

	return hBuffer;
}

v8::Local<v8::Object> String_to_v8Buffer(Handle<std::string> hBuffer) {
	LOG_FUNC();

	LOG_INFO("Copy bio to buffer");
	char *data = (char*)hBuffer->c_str();
	size_t datalen = hBuffer->length();

	v8::Local<v8::Object> v8Buffer = Nan::NewBuffer((uint32_t)datalen).ToLocalChecked();
	char *buffer = node::Buffer::Data(v8Buffer);
	memcpy(buffer, data, datalen);

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