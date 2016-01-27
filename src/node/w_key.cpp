#include "w_key.h"

const char* WKey::ClassName = "Key";

void WKey::Init(v8::Handle<v8::Object> exports) {
	v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
	tpl->SetClassName(Nan::New(WKey::ClassName).ToLocalChecked());
	tpl->InstanceTemplate()->SetInternalFieldCount(1);

	// methods
	SetPrototypeMethod(tpl, "exportJwk", ExportJwk);
	SetPrototypeMethod(tpl, "exportSpki", ExportSpki);
	SetPrototypeMethod(tpl, "exportPkcs8", ExportPkcs8);
	SetPrototypeMethod(tpl, "sign", Sign);
	SetPrototypeMethod(tpl, "verify", Verify);
	SetPrototypeMethod(tpl, "RsaOaepEncDec", RsaOaepEncDec);

	v8::Local<v8::ObjectTemplate> itpl = tpl->InstanceTemplate();
	Nan::SetAccessor(itpl, Nan::New("type").ToLocalChecked(), Type);

	constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

	// static methods
	Nan::SetMethod<v8::Local<v8::Object>>(tpl->GetFunction(), "generateRsa", GenerateRsa);
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

NAN_METHOD(WKey::GenerateRsa) {
	LOG_FUNC();

	int modulus = Nan::To<int>(info[0]).FromJust();
	int publicExponent = Nan::To<int>(info[1]).FromJust();
	Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncRsaGenerateKey(callback, modulus, publicExponent));
}

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

NAN_METHOD(WKey::ExportSpki) {
	LOG_FUNC();

	WKey *wkey = WKey::Unwrap<WKey>(info.This());

	Nan::Callback *callback = new Nan::Callback(info[0].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncExportSpki(callback, wkey->data));
}

NAN_METHOD(WKey::ExportPkcs8) {
	LOG_FUNC();

	WKey *wkey = WKey::Unwrap<WKey>(info.This());

	Nan::Callback *callback = new Nan::Callback(info[0].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncExportPkcs8(callback, wkey->data));
}

NAN_METHOD(WKey::ImportPkcs8) {
	LOG_FUNC();

	Handle<ScopedBIO> in = v8Buffer_to_ScopedBIO(info[0]);

	Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncImportPkcs8(callback, in));
}

/*
 * in: buffer
 */
NAN_METHOD(WKey::ImportSpki) {
	LOG_FUNC();

	Handle<ScopedBIO> in = v8Buffer_to_ScopedBIO(info[0]);

	Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncImportSpki(callback, in));
}

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
		Handle<JwkRsa> jwk(new JwkRsa());

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

		Nan::AsyncQueueWorker(new AsyncImportJwkRsa(callback, jwk, key_type));
	}
	else {
		Nan::ThrowError("JWK: Unsupported kty value");
		return;
	}
}

/*
 * digestName: string
 * data: Buffer
 */
NAN_METHOD(WKey::Sign) {
	LOG_FUNC();

	LOG_INFO("digestName");
	v8::String::Utf8Value v8DigestName(info[0]->ToString());
	const EVP_MD *md = EVP_get_digestbyname(*v8DigestName);
	if (!md) {
		Nan::ThrowError("Unknown digest name");
		return;
	}

	LOG_INFO("data");
	Handle<ScopedBIO> hBio = v8Buffer_to_ScopedBIO(info[1]);

	LOG_INFO("this->Key");
	WKey *wkey = WKey::Unwrap<WKey>(info.This());
	Handle<ScopedEVP_PKEY> pkey = wkey->data;

	Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncSignRsa(callback, md, pkey, hBio));
}

/*
* digestName: string
* data: Buffer
* signature: Buffer
* cb: function
*/
NAN_METHOD(WKey::Verify) {
	LOG_FUNC();

	LOG_INFO("digestName");
	v8::String::Utf8Value v8DigestName(info[0]->ToString());
	const EVP_MD *md = EVP_get_digestbyname(*v8DigestName);
	if (!md) {
		Nan::ThrowError("Unknown digest name");
		return;
	}

	LOG_INFO("data");
	Handle<ScopedBIO> data = v8Buffer_to_ScopedBIO(info[1]);

	LOG_INFO("signature");
	Handle<ScopedBIO> sig = v8Buffer_to_ScopedBIO(info[2]);

	LOG_INFO("this->Key");
	WKey *wkey = WKey::Unwrap<WKey>(info.This());
	Handle<ScopedEVP_PKEY> pkey = wkey->data;

	Nan::Callback *callback = new Nan::Callback(info[3].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncVerifyRsa(callback, md, pkey, data, sig));
}

/*
 * digestName: string
 * data: Buffer
 * label: Buffer
 * decrypt: boolean
 * cb: function
 */
NAN_METHOD(WKey::RsaOaepEncDec) {
	LOG_FUNC();

	LOG_INFO("digestName");
	v8::String::Utf8Value v8DigestName(info[0]->ToString());
	const EVP_MD *md = EVP_get_digestbyname(*v8DigestName);
	if (!md) {
		Nan::ThrowError("Unknown digest name");
		return;
	}

	LOG_INFO("data");
	Handle<ScopedBIO> hData = v8Buffer_to_ScopedBIO(info[1]);

	LOG_INFO("label");
	Handle<ScopedBIO> hLabel(new ScopedBIO(NULL));
	if (!info[2]->IsNull()) {
		hLabel = v8Buffer_to_ScopedBIO(info[2]);
	}

	LOG_INFO("decrypt");
	bool decrypt = info[3]->BooleanValue();

	LOG_INFO("this->Key");
	WKey *wKey = WKey::Unwrap<WKey>(info.This());
	Handle<ScopedEVP_PKEY> hKey = wKey->data;

	Nan::Callback *callback = new Nan::Callback(info[4].As<v8::Function>());

	Nan::AsyncQueueWorker(new AsyncEncrypDecryptRsaOAEP(callback, hKey, md, hData, hLabel, decrypt));
}