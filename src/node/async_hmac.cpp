#include "async_hmac.h"
#include "w_hmac.h"

void AsyncHmacGenerateKey::Execute() {
	try {
		key = ScopedHMAC::generate(keySize);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncHmacGenerateKey::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Key = WHmac::NewInstance();
	WHmac *wkey = WHmac::Unwrap<WHmac>(v8Key);
	wkey->data = this->key;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Key
	};

	callback->Call(2, argv, async_resource);
}

void AsyncHmacExport::Execute() {
	try {
		hOutput = hKey->value;
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncHmacExport::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		String_to_v8Buffer(hOutput)
	};

	callback->Call(2, argv, async_resource);
}

void AsyncHmacImport::Execute() {
	try {
		hKey = Handle<ScopedHMAC>(new ScopedHMAC(hInput));
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncHmacImport::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Key = WHmac::NewInstance();
	WHmac *wkey = WHmac::Unwrap<WHmac>(v8Key);
	wkey->data = this->hKey;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Key
	};

	callback->Call(2, argv, async_resource);
}

void AsyncHmacSign::Execute() {
	try {
		out = this->pkey->sign(in, md);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncHmacSign::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Buffer = String_to_v8Buffer(out);

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Buffer
	};

	callback->Call(2, argv, async_resource);
}

void AsyncHmacVerify::Execute() {
	try {
		res = this->pkey->verify(in, md, signature);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncHmacVerify::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		Nan::New<v8::Boolean>(res)
	};

	callback->Call(2, argv, async_resource);
}
