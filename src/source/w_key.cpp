#include "w_key.h"

const char* WKey::ClassName = "Key";

void WKey::Init(v8::Handle<v8::Object> exports) {
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
	tpl->SetClassName(Nan::New(WKey::ClassName).ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	//generate
	SetPrototypeMethod(tpl, "exportJwk", ExportJwk);
	SetPrototypeMethod(tpl, "exportSpki", ExportSpki);
	SetPrototypeMethod(tpl, "exportPkcs8", ExportPkcs8);

	v8::Local<v8::ObjectTemplate> itpl = tpl->InstanceTemplate();
	Nan::SetAccessor(itpl, Nan::New("type").ToLocalChecked(), Type);

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

NAN_GETTER(WKey::Type) {
	LOG_FUNC();

	WKey *wkey = WKey::Unwrap<WKey>(info.This());
	info.GetReturnValue().Set(Nan::New<v8::Number>(wkey->data->Get()->type));
}

class AsyncRsaGenerateKey : public Nan::AsyncWorker {
public:
	AsyncRsaGenerateKey(Nan::Callback *callback, int modulusBits, int publicExponent)
		: AsyncWorker(callback), modulusBits(modulusBits), publicExponent(publicExponent) {}
	~AsyncRsaGenerateKey() {}

	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
	void Execute() {
		key = RSA_generate(modulusBits, publicExponent);
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

NAN_METHOD(WKey::GenerateRsaAsync) {
	LOG_FUNC();

	int modulus = Nan::To<int>(info[0]).FromJust();
	int publicExponent = Nan::To<int>(info[1]).FromJust();
	Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncRsaGenerateKey(callback, modulus, publicExponent));
}

class AsyncExportJwk : public Nan::AsyncWorker {
public:
	AsyncExportJwk(
		Nan::Callback *callback,
		int key_type,
		Handle<ScopedEVP_PKEY> key,
		v8::Local<v8::Object>(*fn)(EVP_PKEY *pkey, int &key_type))
		: AsyncWorker(callback), isolate(isolate), key_type(key_type), key(key), export_fn(fn) {}
	~AsyncExportJwk() {}

	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
	void Execute() {
	}

	// Executed when the async work is complete
	// this function will be run inside the main event loop
	// so it is safe to use V8 again
	void HandleOKCallback() {
		Nan::HandleScope scope;

		jwk = export_fn(key->Get(), key_type);

		v8::Local<v8::Value> argv[] = {
			jwk
		};

		callback->Call(1, argv);
	}

private:
	v8::Local<v8::Object> jwk;
	int key_type;
	Handle<ScopedEVP_PKEY> key;
	v8::Isolate* isolate;
	v8::Local<v8::Object>(*export_fn)(EVP_PKEY *pkey, int &key_type);
};

NAN_METHOD(WKey::ExportJwk) {
	LOG_FUNC();

	WKey *wkey = WKey::Unwrap<WKey>(info.This());

	int key_type = Nan::To<int>(info[0]).FromJust();

	Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

	try {
		switch (wkey->data->Get()->type) {
		case EVP_PKEY_RSA: {
			Nan::AsyncQueueWorker(new AsyncExportJwk(callback, key_type, wkey->data, &RSA_export_jwk));
			break;
		}
		case EVP_PKEY_EC:
			Nan::ThrowError("Not implemented yet");
			break;
		default:
			Nan::ThrowError("Unknow key type in use");
		}
	}
	catch (std::exception* e) {
		Nan::ThrowError(e->what());
	}
}

class AsyncExportSpki : public Nan::AsyncWorker {
public:
	AsyncExportSpki(Nan::Callback *callback, Handle<ScopedEVP_PKEY>key)
		: AsyncWorker(callback), key(key) {}
	~AsyncExportSpki() {}

	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
	void Execute() {
		buffer = KEY_export_spki(key->Get());
	}

	// Executed when the async work is complete
	// this function will be run inside the main event loop
	// so it is safe to use V8 again
	void HandleOKCallback() {
		Nan::HandleScope scope;

		char* buf;
		int len = BIO_get_mem_data(buffer->Get(), &buf);
		v8::Local<v8::Object> v8Buffer = Nan::NewBuffer(buf, len).ToLocalChecked();

		v8::Local<v8::Value> argv[] = {
			v8Buffer
		};

		callback->Call(1, argv);
	}

private:
	Handle<ScopedBIO> buffer;
	Handle<ScopedEVP_PKEY> key;
};

NAN_METHOD(WKey::ExportSpki) {
	LOG_FUNC();

	WKey *wkey = WKey::Unwrap<WKey>(info.This());

	Nan::Callback *callback = new Nan::Callback(info[0].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncExportSpki(callback, wkey->data));
}

class AsyncExportPkcs8 : public Nan::AsyncWorker {
public:
	AsyncExportPkcs8(Nan::Callback *callback, Handle<ScopedEVP_PKEY>key)
		: AsyncWorker(callback), key(key) {}
	~AsyncExportPkcs8() {}

	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
	void Execute() {
		buffer = KEY_export_pkcs8(key->Get());
	}

	// Executed when the async work is complete
	// this function will be run inside the main event loop
	// so it is safe to use V8 again
	void HandleOKCallback() {
		Nan::HandleScope scope;

		char* buf;
		int len = BIO_get_mem_data(buffer->Get(), &buf);
		v8::Local<v8::Object> v8Buffer = Nan::NewBuffer(buf, len).ToLocalChecked();

		v8::Local<v8::Value> argv[] = {
			v8Buffer
		};

		callback->Call(1, argv);
	}

private:
	Handle<ScopedBIO> buffer;
	Handle<ScopedEVP_PKEY> key;
};

NAN_METHOD(WKey::ExportPkcs8) {
	LOG_FUNC();

	WKey *wkey = WKey::Unwrap<WKey>(info.This());

	Nan::Callback *callback = new Nan::Callback(info[0].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncExportPkcs8(callback, wkey->data));
}