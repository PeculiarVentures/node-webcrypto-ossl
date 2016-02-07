#include "async_core.h"

#include "common.h"

void AsyncDigest::Execute() {
	try {
		const EVP_MD* md = EVP_get_digestbyname(hDigestName->c_str());

		hDigest = digest(md, hBuffer);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncDigest::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		String_to_v8Buffer(hDigest)
	};

	callback->Call(2, argv);
}