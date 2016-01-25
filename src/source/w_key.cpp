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
	Nan::SetMethod<v8::Local<v8::Object>>(tpl->GetFunction(), "importPkcs8", ImportPkcs8);
	Nan::SetMethod<v8::Local<v8::Object>>(tpl->GetFunction(), "importJwk", ImportJwk);
	Nan::SetMethod<v8::Local<v8::Object>>(tpl->GetFunction(), "importSpki", ImportSpki);

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
		try {
			key = RSA_generate(modulusBits, publicExponent);
		}
		catch (std::exception& e) {
			this->SetErrorMessage(e.what());
		}
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

class AsyncExportJwkRsa : public Nan::AsyncWorker {
public:
	AsyncExportJwkRsa(
		Nan::Callback *callback,
		int key_type,
		Handle<ScopedEVP_PKEY> key)
		: AsyncWorker(callback), key_type(key_type), key(key) {}
	~AsyncExportJwkRsa() {}

	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
	void Execute() {
		try {
			jwk = RSA_export_jwk(key->Get(), key_type);
		}
		catch (std::exception& e) {
			this->SetErrorMessage(e.what());
		}
	}

	// Executed when the async work is complete
	// this function will be run inside the main event loop
	// so it is safe to use V8 again
	void HandleOKCallback() {
		Nan::HandleScope scope;

		v8::Local<v8::Object> v8Jwk = Nan::New<v8::Object>();

		LOG_INFO("Convert RSA to JWK");
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_KTY).ToLocalChecked(), Nan::New(jwk->Get()->kty).ToLocalChecked());
		LOG_INFO("Get RSA public key");
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_N).ToLocalChecked(), bn2buf(jwk->Get()->n.Get()));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_E).ToLocalChecked(), bn2buf(jwk->Get()->e.Get()));
		if (key_type == NODESSL_KT_PRIVATE) {
			LOG_INFO("Get RSA private key");
			Nan::Set(v8Jwk, Nan::New(JWK_ATTR_D).ToLocalChecked(), bn2buf(jwk->Get()->d.Get()));
			Nan::Set(v8Jwk, Nan::New(JWK_ATTR_P).ToLocalChecked(), bn2buf(jwk->Get()->p.Get()));
			Nan::Set(v8Jwk, Nan::New(JWK_ATTR_Q).ToLocalChecked(), bn2buf(jwk->Get()->q.Get()));
			Nan::Set(v8Jwk, Nan::New(JWK_ATTR_DP).ToLocalChecked(), bn2buf(jwk->Get()->dp.Get()));
			Nan::Set(v8Jwk, Nan::New(JWK_ATTR_DQ).ToLocalChecked(), bn2buf(jwk->Get()->dq.Get()));
			Nan::Set(v8Jwk, Nan::New(JWK_ATTR_QI).ToLocalChecked(), bn2buf(jwk->Get()->qi.Get()));
		}

		v8::Local<v8::Value> argv[] = {
			v8Jwk
		};

		callback->Call(1, argv);
	}

private:
	Handle<ScopedJWK_RSA> jwk;
	int key_type;
	Handle<ScopedEVP_PKEY> key;
};

/*
 * key_type: number
 * cb: function
 */
NAN_METHOD(WKey::ExportJwk) {
	LOG_FUNC();

	WKey *wkey = WKey::Unwrap<WKey>(info.This());

	int key_type = Nan::To<int>(info[0]).FromJust();

	Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

	try {
		switch (wkey->data->Get()->type) {
		case EVP_PKEY_RSA: {
			Nan::AsyncQueueWorker(new AsyncExportJwkRsa(callback, key_type, wkey->data));
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
		try {
			buffer = KEY_export_spki(key->Get());
		}
		catch (std::exception& e) {
			this->SetErrorMessage(e.what());
		}
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
		try {
			buffer = KEY_export_pkcs8(key->Get());
		}
		catch (std::exception& e) {
			this->SetErrorMessage(e.what());
		}
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

class AsyncImportPkcs8 : public Nan::AsyncWorker {
public:
	AsyncImportPkcs8(Nan::Callback *callback, BIO* in)
		: AsyncWorker(callback), in(in) {}
	~AsyncImportPkcs8() {}

	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
	void Execute() {
		try {
			key = KEY_import_pkcs8(in);
		}
		catch (std::exception& e) {
			this->SetErrorMessage(e.what());
		}
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
	BIO *in;
	Handle<ScopedEVP_PKEY> key;
};

NAN_METHOD(WKey::ImportPkcs8) {
	LOG_FUNC();

	v8::Local<v8::Object> v8Buffer = info[0]->ToObject();
	BIO *in = BIO_new_mem_buf(node::Buffer::Data(v8Buffer), node::Buffer::Length(v8Buffer));

	Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncImportPkcs8(callback, in));
}

class AsyncImportSpki : public Nan::AsyncWorker {
public:
	AsyncImportSpki(Nan::Callback *callback, BIO* in)
		: AsyncWorker(callback), in(in) {}
	~AsyncImportSpki() {}

	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
	void Execute() {
		try {
			key = KEY_import_spki(in);
		}
		catch (std::exception& e) {
			this->SetErrorMessage(e.what());
		}
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
	BIO *in;
	Handle<ScopedEVP_PKEY> key;
};

NAN_METHOD(WKey::ImportSpki) {
	LOG_FUNC();

	v8::Local<v8::Object> v8Buffer = info[0]->ToObject();
	BIO *in = BIO_new_mem_buf(node::Buffer::Data(v8Buffer), node::Buffer::Length(v8Buffer));

	Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncImportSpki(callback, in));
}

class AsyncImportJwkRsa : public Nan::AsyncWorker {
public:
	AsyncImportJwkRsa(Nan::Callback *callback, Handle<ScopedJWK_RSA> jwk, int key_type)
		: AsyncWorker(callback), jwk(jwk), key_type(key_type) {}
	~AsyncImportJwkRsa() {}

	// Executed inside the worker-thread.
	// It is not safe to access V8, or V8 data structures
	// here, so everything we need for input and output
	// should go on `this`.
	void Execute() {
		try {
			pkey = RSA_import_jwk(jwk, key_type);
		}
		catch (std::exception& e) {
			this->SetErrorMessage(e.what());
		}
	}

	// Executed when the async work is complete
	// this function will be run inside the main event loop
	// so it is safe to use V8 again
	void HandleOKCallback() {
		Nan::HandleScope scope;

		v8::Local<v8::Object> v8Key = WKey::NewInstance();
		WKey *wkey = WKey::Unwrap<WKey>(v8Key);
		wkey->data = pkey;

		v8::Local<v8::Value> argv[] = {
			v8Key
		};

		callback->Call(1, argv);
	}

private:
	int key_type;
	Handle<ScopedEVP_PKEY> pkey;
	Handle<ScopedJWK_RSA> jwk;
};

/*
 * jwk: v8::Object
 * key_type: number
 */
NAN_METHOD(WKey::ImportJwk) {
	LOG_FUNC();

	int key_type = Nan::To<int>(info[1]).FromJust();

	Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());

	v8::Local<v8::Object> v8Jwk = info[0]->ToObject();
	v8::String::Utf8Value v8Kty(Nan::Get(v8Jwk, Nan::New(JWK_ATTR_KTY).ToLocalChecked()).ToLocalChecked());

	if (strcmp(*v8Kty, JWK_KTY_RSA) == 0) {
		JWK_RSA *jwk = JWK_RSA_new();
		Handle<ScopedJWK_RSA> hJwk(new ScopedJWK_RSA(jwk));

		LOG_INFO("set public key");
		v8Object_get_BN(v8Jwk, n, jwk, n);
		v8Object_get_BN(v8Jwk, e, jwk, e);

		if (key_type == NODESSL_KT_PRIVATE) {
			LOG_INFO("set private key");
			v8Object_get_BN(v8Jwk, d, jwk, d);
			v8Object_get_BN(v8Jwk, p, jwk, p);
			v8Object_get_BN(v8Jwk, q, jwk, q);
			v8Object_get_BN(v8Jwk, dp, jwk, dp);
			v8Object_get_BN(v8Jwk, dq, jwk, dq);
			v8Object_get_BN(v8Jwk, qi, jwk, qi);
		}

		Nan::AsyncQueueWorker(new AsyncImportJwkRsa(callback, hJwk, key_type));
	}
	else {
		Nan::ThrowError("JWK: Unsupported kty value");
		return;
	}
}