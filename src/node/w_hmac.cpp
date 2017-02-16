#include "w_hmac.h"

const char* WHmac::ClassName = "HmacKey";

void WHmac::Init(v8::Handle<v8::Object> exports) {
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
	tpl->SetClassName(Nan::New(ClassName).ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	// methods

	SetPrototypeMethod(tpl, "export", Export);
	SetPrototypeMethod(tpl, "sign", Sign);
	SetPrototypeMethod(tpl, "verify", Verify);

	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	// static methods
	Nan::SetMethod(tpl->GetFunction(), "generate", Generate);
	Nan::SetMethod(tpl->GetFunction(), "import", Import);

	exports->Set(Nan::New(ClassName).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WHmac::New) {
	LOG_FUNC();

	if (info.IsConstructCall()) {

		WHmac * obj = new WHmac();
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

/*
* keySize: number
* cb: function
*/
NAN_METHOD(WHmac::Generate) {
	LOG_FUNC();

	int keySize = Nan::To<int>(info[0]).FromJust();
	Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncHmacGenerateKey(callback, keySize));
}

/*
* cb: function
*/
NAN_METHOD(WHmac::Export) {
	LOG_FUNC();

	LOG_INFO("this");
	WHmac *that = WHmac::Unwrap<WHmac>(info.This());

	Nan::Callback *callback = new Nan::Callback(info[0].As<v8::Function>());
	Nan::AsyncQueueWorker(new AsyncHmacExport(callback, that->data));
}

/*
* raw: buffer
* cb: function
*/
NAN_METHOD(WHmac::Import) {
	LOG_FUNC();

	LOG_INFO("raw");
	Handle<std::string> hRaw = v8Buffer_to_String(info[0]);

	Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());
	Nan::AsyncQueueWorker(new AsyncHmacImport(callback, hRaw));
}

/*
* digestName: string
* data: Buffer
*/
NAN_METHOD(WHmac::Sign) {
	LOG_FUNC();

	LOG_INFO("digestName");
	v8::String::Utf8Value v8DigestName(info[0]->ToString());
	const EVP_MD *md = EVP_get_digestbyname(*v8DigestName);
	if (!md) {
		Nan::ThrowError("Unknown digest name");
		return;
	}

	LOG_INFO("data");
	Handle<std::string> hBio = v8Buffer_to_String(info[1]);

	LOG_INFO("this->Key");
	WHmac *that = WHmac::Unwrap<WHmac>(info.This());

	LOG_INFO("Check key HMAC");
	switch (that->data->type) {
	case EVP_PKEY_HMAC:
		break;
	default:
		v8::Local<v8::Value> argv[] = {
			Nan::New("Unsupported Key in use").ToLocalChecked()
		};

		Nan::CallAsFunction(Nan::To<v8::Object>(info[2]).ToLocalChecked(), info.This(), 1, argv);
		return;
	}

	Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());
	Nan::AsyncQueueWorker(new AsyncHmacSign(callback, md, that->data, hBio));
}

/*
* digestName: string
* data: Buffer
* signature: Buffer
* cb: function
*/
NAN_METHOD(WHmac::Verify) {
	LOG_FUNC();

	LOG_INFO("digestName");
	v8::String::Utf8Value v8DigestName(info[0]->ToString());
	const EVP_MD *md = EVP_get_digestbyname(*v8DigestName);
	if (!md) {
		Nan::ThrowError("Unknown digest name");
		return;
	}

	LOG_INFO("data");
	Handle<std::string> data = v8Buffer_to_String(info[1]);

	LOG_INFO("signature");
	Handle<std::string> sig = v8Buffer_to_String(info[2]);

	LOG_INFO("this->Key");
	WHmac *that = WHmac::Unwrap<WHmac>(info.This());
	Handle<ScopedHMAC> pkey = that->data;

	LOG_INFO("Check key HMAC");
	switch (pkey->type) {
	case EVP_PKEY_HMAC:
		break;
	default:
		v8::Local<v8::Value> argv[] = {
			Nan::New("Unsupported Key in use").ToLocalChecked()
		};

		Nan::CallAsFunction(Nan::To<v8::Object>(info[2]).ToLocalChecked(), info.This(), 1, argv);
		return;
	}

	Nan::Callback *callback = new Nan::Callback(info[3].As<v8::Function>());
	Nan::AsyncQueueWorker(new AsyncHmacVerify(callback, md, pkey, data, sig));

}
