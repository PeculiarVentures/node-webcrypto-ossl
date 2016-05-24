#include "w_core.h"

const char* WCore::ClassName = "Core";

void WCore::Init(v8::Handle<v8::Object> exports) {
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
	tpl->SetClassName(Nan::New(ClassName).ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	// methods

	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	// static methods
	Nan::SetMethod(tpl->GetFunction(), "digest", Digest);

	exports->Set(Nan::New(ClassName).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WCore::New) {
	LOG_FUNC();

	if (info.IsConstructCall()) {

		WCore* obj = new WCore();
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
* digestName: string
* message: Buffer
* cb: function(err: Error, digest: Buffer)
*/
NAN_METHOD(WCore::Digest) {
	LOG_FUNC();

	LOG_INFO("digestName");
	v8::String::Utf8Value v8DigestName(info[0]->ToString());
	Handle<std::string> hDigestName(new std::string(*v8DigestName));

	LOG_INFO("message");
	Handle<std::string> hMessage = v8Buffer_to_String(info[1]);

	Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());
	Nan::AsyncQueueWorker(new AsyncDigest(callback, hDigestName, hMessage));
}