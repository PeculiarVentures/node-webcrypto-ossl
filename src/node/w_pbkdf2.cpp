#include "w_pbkdf2.h"

const char* WPbkdf2::ClassName = "Pbkdf2Key";

NAN_MODULE_INIT(WPbkdf2::Init) {
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
	tpl->SetClassName(Nan::New(ClassName).ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	// methods

	SetPrototypeMethod(tpl, "deriveBits", DeriveBits);

	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	// static methods
	Nan::SetMethod(Nan::GetFunction(tpl).ToLocalChecked(), "importKey", ImportKey);

    Nan::Set(target,
             Nan::New(ClassName).ToLocalChecked(),
             Nan::GetFunction(tpl).ToLocalChecked());
}

NAN_METHOD(WPbkdf2::New) {
	LOG_FUNC();

	if (info.IsConstructCall()) {

		WPbkdf2 * obj = new WPbkdf2();
		obj->Wrap(info.This());
		info.GetReturnValue().Set(info.This());
	}
	else {
		//const int argc = 1;
		//v8::Local<v8::Value> argv[argc] = { info[0] };
		v8::Local<v8::Function> cons = Nan::New(constructor());
		info.GetReturnValue().Set(Nan::NewInstance(cons, 0, nullptr).ToLocalChecked());
	}
};

/**
 * raw: buffer
 * cb: (error: Error, data: Pbkdf2Key) => void
 */
NAN_METHOD(WPbkdf2::ImportKey) {
	LOG_FUNC();

	LOG_INFO("raw");
	Handle<std::string> hRaw = v8Buffer_to_String(info[0]);

	Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());
	Nan::AsyncQueueWorker(new AsyncPbkdf2Import(callback, hRaw));
}

/**
 * digestName: string
 * salt: Buffer
 * iterations: number
 * bits_length: number
 * cb: (error: Error, data: Buffer) => void
 */
NAN_METHOD(WPbkdf2::DeriveBits) {
	LOG_FUNC();

	LOG_INFO("digestName");
    Nan::Utf8String nanDigestName(Nan::To<v8::String>(info[0]).ToLocalChecked());
	const EVP_MD *md = EVP_get_digestbyname(*nanDigestName);

	LOG_INFO("salt");
	Handle<std::string> salt = v8Buffer_to_String(info[1]);

	LOG_INFO("iterations");
	int iterations = Nan::To<int>(info[2]).FromJust();

	LOG_INFO("bits_length");
	int bits_length= Nan::To<int>(info[3]).FromJust();

	LOG_INFO("this->Key");
	WPbkdf2 *that = WPbkdf2::Unwrap<WPbkdf2>(info.This());

	LOG_INFO("Check key Pbkdf2Key");
	switch (that->data->type) {
	case EVP_PKEY_PBKDF2:
		break;
	default:
		v8::Local<v8::Value> argv[] = {
			Nan::New("Unsupported Key in use").ToLocalChecked()
		};

        Nan::CallAsFunction(Nan::To<v8::Object>(info[4]).ToLocalChecked(), info.This(), 1, argv);
		return;
	}

	Nan::Callback *callback = new Nan::Callback(info[4].As<v8::Function>());
	Nan::AsyncQueueWorker(new AsyncPbkdf2DeriveBits(callback, that->data, md, salt, iterations, bits_length));
}
