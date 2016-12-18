#include "async_ec.h"
#include "w_key.h"

void AsyncEcGenerateKey::Execute() {
	try {
		key = EC_generate(namedCurve);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEcGenerateKey::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Key = WKey::NewInstance();
	WKey *wkey = WKey::Unwrap<WKey>(v8Key);
	wkey->data = this->key;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Key
	};

	callback->Call(2, argv);
}

void AsyncEcdhDeriveKey::Execute() {
	try {
		dkey = ECDH_derive_key(pkey, pubkey, secret_len);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEcdhDeriveKey::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		String_to_v8Buffer(dkey)
	};

	callback->Call(2, argv);
}

void AsyncEcExportJwk::Execute() {
	try {
		jwk = JwkEc::From(key, key_type);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEcExportJwk::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Jwk = Nan::New<v8::Object>();

	LOG_INFO("Convert EC to JWK");
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_KTY).ToLocalChecked(), Nan::New(jwk->kty).ToLocalChecked());
	LOG_INFO("Get EC public key");
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_CRV).ToLocalChecked(), Nan::New<v8::Number>(jwk->crv));
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_X).ToLocalChecked(), bn2buf(jwk->x.Get()));
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_Y).ToLocalChecked(), bn2buf(jwk->y.Get()));
	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("Get RSA private key");
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_D).ToLocalChecked(), bn2buf(jwk->d.Get()));
	}

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Jwk
	};

	callback->Call(2, argv);
}

void AsyncEcImportJwk::Execute() {
	try {
		pkey = jwk->To(key_type);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEcImportJwk::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Key = WKey::NewInstance();
	WKey *wkey = WKey::Unwrap<WKey>(v8Key);
	wkey->data = pkey;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Key
	};

	callback->Call(2, argv);
}

void AsyncEcdsaSign::Execute() {
	try {
		out = EC_DSA_sign(pkey, md, in);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEcdsaSign::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Buffer = String_to_v8Buffer(out);

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Buffer
	};

	callback->Call(2, argv);
}

void AsyncEcdsaVerify::Execute() {
	try {
		res = EC_DSA_verify(pkey, md, in, signature);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEcdsaVerify::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		Nan::New<v8::Boolean>(res)
	};

	callback->Call(2, argv);
}

void AsyncEcdhDeriveBits::Execute() {
	try {
		this->dbits = ECDH_derive_bits(pubkey, pkey, length_bits, (unsigned int)length_bits);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEcdhDeriveBits::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		String_to_v8Buffer(this->dbits)
	};

	callback->Call(2, argv);
}