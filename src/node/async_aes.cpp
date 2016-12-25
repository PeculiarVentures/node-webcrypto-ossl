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
			hOutput = hKey->encryptCbc(hInput, hIv);
		}
		else {
			hOutput = hKey->decryptCbc(hInput, hIv);
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
		String_to_v8Buffer(hOutput)
	};

	callback->Call(2, argv);
}

void AsyncAesExport::Execute() {
	try {
		hOutput = hKey->value;
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncAesExport::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		String_to_v8Buffer(hOutput)
	};

	callback->Call(2, argv);
}

void AsyncAesImport::Execute() {
	try {
		hKey = Handle<ScopedAES>(new ScopedAES(hInput));
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncAesImport::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Key = WAes::NewInstance();
	WAes *wkey = WAes::Unwrap<WAes>(v8Key);
	wkey->data = this->hKey;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Key
	};

	callback->Call(2, argv);
}

void AsyncAesEncryptGCM::Execute() {
	try {
		if (encrypt) {
			hOutput = hKey->encryptGcm(hInput, hIv, hAad, tagSize);
		}
		else {
			hOutput = hKey->decryptGcm(hInput, hIv, hAad, tagSize);
		}
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncAesEncryptGCM::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		String_to_v8Buffer(hOutput)
	};

	callback->Call(2, argv);
}

void AsyncAesWrapKey::Execute() {
	try {
		if (encrypt) {
			hOutput = hKey->wrap(hInput);
		}
		else {
			hOutput = hKey->unwrap(hInput);
		}
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncAesWrapKey::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		String_to_v8Buffer(hOutput)
	};

	callback->Call(2, argv);
}
