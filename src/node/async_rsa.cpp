#include "async_rsa.h"

void AsyncEncrypDecryptRsaOAEP::Execute() {
	try {
		result = RSA_OAEP_enc_dec(params->hKey, params->md, params->hData, params->hLabel, params->decrypt);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEncrypDecryptRsaOAEP::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		ScopedBIO_to_v8Buffer(result)
	};

	callback->Call(2, argv);
}

/*
AsyncEncrypDecryptRsaOAEP::AsyncEncrypDecryptRsaOAEP(
	Nan::Callback *callback,
	Handle<ScopedEVP_PKEY> hKey,
	const EVP_MD *md,
	Handle<ScopedBIO> hData,
	Handle<ScopedBIO> hLabel,
	bool decrypt
	)
	: AsyncWorker(callback), hKey(hKey), md(md), hData(hData), hLabel(hLabel), decrypt(decrypt) {}
AsyncEncrypDecryptRsaOAEP::~AsyncEncrypDecryptRsaOAEP() {}

// Executed inside the worker-thread.
// It is not safe to access V8, or V8 data structures
// here, so everything we need for input and output
// should go on `this`.
void AsyncEncrypDecryptRsaOAEP::Execute() {
	try {
		hResult = RSA_OAEP_enc_dec(hKey, md, hData, hLabel, decrypt);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

// Executed when the async work is complete
// this function will be run inside the main event loop
// so it is safe to use V8 again
void AsyncEncrypDecryptRsaOAEP::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		ScopedBIO_to_v8Buffer(hResult)
	};

	callback->Call(2, argv);
}
*/