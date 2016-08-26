#include "async_rsa.h"

void AsyncEncrypDecryptRsaOAEP::Execute() {
	try {
		hResult = RSA_OAEP_enc_dec(hKey, md, hData, hLabel, decrypt);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncEncrypDecryptRsaOAEP::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		String_to_v8Buffer(hResult)
	};

	callback->Call(2, argv);
}

void AsyncRsaGenerateKey::Execute() {
	try {
		key = RSA_generate(modulusBits, publicExponent);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncRsaGenerateKey::HandleOKCallback() {
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


void AsyncExportJwkRsa::Execute() {
	try {
		jwk = JwkRsa::From(key, key_type);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncExportJwkRsa::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Jwk = Nan::New<v8::Object>();

	LOG_INFO("Convert RSA to JWK");
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_KTY).ToLocalChecked(), Nan::New(jwk->kty).ToLocalChecked());
	LOG_INFO("Get RSA public key");
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_N).ToLocalChecked(), bn2buf(jwk->n.Get()));
	Nan::Set(v8Jwk, Nan::New(JWK_ATTR_E).ToLocalChecked(), bn2buf(jwk->e.Get()));
	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("Get RSA private key");
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_D).ToLocalChecked(), bn2buf(jwk->d.Get()));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_P).ToLocalChecked(), bn2buf(jwk->p.Get()));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_Q).ToLocalChecked(), bn2buf(jwk->q.Get()));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_DP).ToLocalChecked(), bn2buf(jwk->dp.Get()));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_DQ).ToLocalChecked(), bn2buf(jwk->dq.Get()));
		Nan::Set(v8Jwk, Nan::New(JWK_ATTR_QI).ToLocalChecked(), bn2buf(jwk->qi.Get()));
	}

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Jwk
	};

	callback->Call(2, argv);
}

void AsyncExportSpki::Execute() {
	try {
		buffer = KEY_export_spki(key->Get());
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncExportSpki::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Buffer = String_to_v8Buffer(buffer);

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Buffer
	};

	callback->Call(2, argv);
}

void AsyncExportPkcs8::Execute() {
	try {
		buffer = KEY_export_pkcs8(key->Get());
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}


void AsyncExportPkcs8::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Buffer = String_to_v8Buffer(buffer);

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Buffer
	};

	callback->Call(2, argv);
}


void AsyncImportPkcs8::Execute() {
	try {
		key = KEY_import_pkcs8(in);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncImportPkcs8::HandleOKCallback() {
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


void AsyncImportSpki::Execute() {
	try {
		key = KEY_import_spki(in);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncImportSpki::HandleOKCallback() {
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


void AsyncImportJwkRsa::Execute() {
	try {
		pkey = jwk->To(key_type);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}


void AsyncImportJwkRsa::HandleOKCallback() {
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


void AsyncSignRsa::Execute() {
	try {
		out = RSA_PKCS1_sign(pkey, md, in);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncSignRsa::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Buffer = String_to_v8Buffer(out);

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Buffer
	};

	callback->Call(2, argv);
}

void AsyncVerifyRsa::Execute() {
	try {
		res = RSA_PKCS1_verify(pkey, md, in, signature);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncVerifyRsa::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		Nan::New<v8::Boolean>(res)
	};

	callback->Call(2, argv);
}

void AsyncSignRsaPSS::Execute() {
	try {
		out = RSA_PSS_sign(pkey, md, saltLen, in);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncSignRsaPSS::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Object> v8Buffer = String_to_v8Buffer(out);

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		v8Buffer
	};

	callback->Call(2, argv);
}

void AsyncVerifyRsaPSS::Execute() {
	try {
		res = RSA_PSS_verify(pkey, md, saltLen, in, signature);
	}
	catch (std::exception& e) {
		this->SetErrorMessage(e.what());
	}
}

void AsyncVerifyRsaPSS::HandleOKCallback() {
	Nan::HandleScope scope;

	v8::Local<v8::Value> argv[] = {
		Nan::Null(),
		Nan::New<v8::Boolean>(res)
	};

	callback->Call(2, argv);
}