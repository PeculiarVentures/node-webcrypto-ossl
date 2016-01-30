#include "async_aes.h"
#include "w_aes.h"

void AsyncAesGenerateKey::Execute() {
	try {
		key = ScopedAES::generate(keySize);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncAesGenerateKey::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Key = WAes::NewInstance();
	WAes *wkey = WAes::Unwrap<WAes>(v8Key);
	wkey->data = this->key;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Key
	};

	callback->Call(2, argv);
}

void AsyncAesEncryptCBC::Execute() {
	try {
		if (encrypt) {
			hOutput = hKey->encrypt(hKey, hInput, hIv);
		}
		else {
			hOutput = hKey->decrypt(hKey, hInput, hIv);
		}
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncAesEncryptCBC::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		ScopedBIO_to_v8Buffer(hOutput)
	};

	callback->Call(2, argv);
}