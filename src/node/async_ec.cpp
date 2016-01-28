#include "async_ec.h"
#include "w_key.h"

void AsyncEcGenerateKey::Execute() {
	try {
		key = EC_generate(namedCurve);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEcGenerateKey::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Key = WKey::NewInstance();
	WKey *wkey = WKey::Unwrap<WKey>(v8Key);
	wkey->data = this->key;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Key
	};

	callback->Call(2, argv);
}