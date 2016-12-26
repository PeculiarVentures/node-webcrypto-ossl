#include "async_pbkdf2.h"
#include "w_pbkdf2.h"

void AsyncPbkdf2Import::Execute() {
	try {
		hKey = Handle<ScopedPbkdf2>(new ScopedPbkdf2(this->hInput));
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncPbkdf2Import::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Key = WPbkdf2::NewInstance();
	WPbkdf2 *wkey = WPbkdf2::Unwrap<WPbkdf2>(v8Key);
	wkey->data = this->hKey;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Key
	};

	callback->Call(2, argv);
}

void AsyncPbkdf2DeriveBits::Execute() {
	try {
		res = this->pkey->deriveBits(salt, (size_t)iterations, md, (size_t)bits_length);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncPbkdf2DeriveBits::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		String_to_v8Buffer(res)
	};

	callback->Call(2, argv);
}