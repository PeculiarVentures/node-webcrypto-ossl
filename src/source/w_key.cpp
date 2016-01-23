#include "w_key.h";

const char* WKey::ClassName = "Key";

void WKey::Init(v8::Handle<v8::Object> exports) {
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
	tpl->SetClassName(Nan::New(WKey::ClassName).ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	//generate
	//SetPrototypeMethod(tpl, "generateRsa", GenerateRsa);

	v8::Local<v8::ObjectTemplate> itpl = tpl->InstanceTemplate();
	//Nan::SetAccessor(itpl, Nan::New("type").ToLocalChecked(), Type);

	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	//static functions
	Nan::SetMethod<v8::Local<v8::Object>>(tpl->GetFunction(), "generateRsa", GenerateRsaAsync);

	exports->Set(Nan::New(WKey::ClassName).ToLocalChecked(), tpl->GetFunction());
}

NAN_METHOD(WKey::New) {
	LOG_FUNC();

	if (info.IsConstructCall()) {

		WKey * obj = new WKey();
		obj->Wrap(info.This());
		info.GetReturnValue().Set(info.This());

	}
	else {
		//const int argc = 1;
		//v8::Local<v8::Value> argv[argc] = { info[0] };
		v8::Local<v8::Function> cons = Nan::New(constructor());
		info.GetReturnValue().Set(Nan::NewInstance(cons, 0, NULL).ToLocalChecked());
	}
};

class RsaGenerateKeyAsync : public Nan::AsyncWorker {
public:
	RsaGenerateKeyAsync(Nan::Callback *callback, int modulusBits, int publicExponent)
		: AsyncWorker(callback), modulusBits(modulusBits), publicExponent(publicExponent) {}
	~RsaGenerateKeyAsync() {}

	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
	void Execute() {
		key = generateRsa(modulusBits, publicExponent);
	}

	// Executed when the async work is complete
	// this function will be run inside the main event loop
	// so it is safe to use V8 again
	void HandleOKCallback() {
		Nan::HandleScope scope;

		v8::Local<v8::Object> v8Key = WKey::NewInstance();
		WKey *wkey = WKey::Unwrap<WKey>(v8Key);
		wkey->data = this->key;

		v8::Local<v8::Value> argv[] = {
			v8Key
		};

		callback->Call(1, argv);
	}

private:
	int modulusBits;
	int publicExponent;
	Handle<ScopedEVP_PKEY> key;
};

NAN_METHOD(GenerateRsaAsync) {
	LOG_FUNC();

	int modulus = Nan::To<int>(info[0]).FromJust();
	int publicExponent = Nan::To<int>(info[1]).FromJust();
	Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());

	Nan::AsyncQueueWorker(new RsaGenerateKeyAsync(callback, modulus, publicExponent));
}