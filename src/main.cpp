#include "node/common.h"

#define SET_ENUM(obj, name, value)												\
	obj->Set(Nan::New(#name).ToLocalChecked(), Nan::New<v8::Number>(value));	\
	obj->Set(value, Nan::New(#name).ToLocalChecked());

void EcNamedCurves(v8::Handle<v8::Object> target) {
	v8::Local<v8::Object> ecNamedCurves = Nan::New<v8::Object>();
#define SET_NAMED_CURVE(namedCurve)												\
	SET_ENUM(ecNamedCurves, namedCurve, NID_##namedCurve);

	SET_NAMED_CURVE(secp112r1);
	SET_NAMED_CURVE(secp112r2);
	SET_NAMED_CURVE(secp128r1);
	SET_NAMED_CURVE(secp128r2);
	SET_NAMED_CURVE(secp160k1);
	SET_NAMED_CURVE(secp160r1);
	SET_NAMED_CURVE(secp160r2);
	SET_ENUM(ecNamedCurves, secp192r1, 409);
	SET_NAMED_CURVE(secp192k1);
	SET_NAMED_CURVE(secp224k1);
	SET_NAMED_CURVE(secp224r1);
	SET_NAMED_CURVE(secp256k1);
	SET_ENUM(ecNamedCurves, secp256r1, 415);
	SET_NAMED_CURVE(secp384r1);
	SET_NAMED_CURVE(secp521r1);
	SET_NAMED_CURVE(sect113r1);
	SET_NAMED_CURVE(sect113r2);
	SET_NAMED_CURVE(sect131r1);
	SET_NAMED_CURVE(sect131r2);
	SET_NAMED_CURVE(sect163k1);
	SET_NAMED_CURVE(sect163r1);
	SET_NAMED_CURVE(sect163r2);
	SET_NAMED_CURVE(sect193r1);
	SET_NAMED_CURVE(sect193r2);
	SET_NAMED_CURVE(sect233k1);
	SET_NAMED_CURVE(sect233r1);
	SET_NAMED_CURVE(sect239k1);
	SET_NAMED_CURVE(sect283k1);
	SET_NAMED_CURVE(sect283r1);
	SET_NAMED_CURVE(sect409k1);
	SET_NAMED_CURVE(sect409r1);
	SET_NAMED_CURVE(sect571k1);
	SET_NAMED_CURVE(sect571r1);

	target->Set(Nan::New("EcNamedCurves").ToLocalChecked(), ecNamedCurves);

#undef SET_NAMED_CURVE
}

void RsaPublicExponent(v8::Handle<v8::Object> target) {
	v8::Local<v8::Object> rsaPublicExponent = Nan::New<v8::Object>();

	SET_ENUM(rsaPublicExponent, RSA_3, 0);
	SET_ENUM(rsaPublicExponent, RSA_F4, 1);

	target->Set(Nan::New("RsaPublicExponent").ToLocalChecked(), rsaPublicExponent);
}

void KeyType(v8::Handle<v8::Object> target) {
	v8::Local<v8::Object> keyType = Nan::New<v8::Object>();

	SET_ENUM(keyType, PUBLIC, 0);
	SET_ENUM(keyType, PRIVATE, 1);

	target->Set(Nan::New("KeyType").ToLocalChecked(), keyType);
}

NAN_MODULE_INIT(InitModule) {

	Nan::HandleScope scope;

	OPENSSL_init();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	WKey::Init(target);
	WAes::Init(target);
	WHmac::Init(target);
	WPbkdf2::Init(target);
	WCore::Init(target);

	// Enums
	EcNamedCurves(target);
	RsaPublicExponent(target);
	KeyType(target);

}

NODE_MODULE(nodessl, InitModule);