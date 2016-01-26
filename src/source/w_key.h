#ifndef OSSL_W_KEY_H_INCLUDE
#define OSSL_W_KEY_H_INCLUDE

#include "key_rsa.h"

using namespace node;

#define v8Object_get_BN(v8Obj, v8Param, RsaKey, RsaKeyParam) \
	{unsigned char* v8Param = (unsigned char*)node::Buffer::Data(Nan::Get(v8Obj, Nan::New(#v8Param).ToLocalChecked()).ToLocalChecked()->ToObject()); \
	RsaKey->RsaKeyParam = BN_bin2bn(v8Param, node::Buffer::Length(Nan::Get(v8Obj, Nan::New(#v8Param).ToLocalChecked()).ToLocalChecked()->ToObject()), NULL);}

class WKey : public ObjectWrap {
public:
	static v8::Local<v8::Object> NewInstance() {
		v8::Local<v8::Function> cons = Nan::New(constructor());
		return Nan::NewInstance(cons).ToLocalChecked();
	}
	static v8::Local<v8::Object> NewInstance(int argc, v8::Local<v8::Value> argv[]) {
		v8::Local<v8::Function> cons = Nan::New(constructor());
		return Nan::NewInstance(cons, argc, argv).ToLocalChecked();
	}

	static const char* ClassName;

	static void Init(v8::Handle<v8::Object> exports);
	
	static NAN_METHOD(New);
	
	static NAN_GETTER(Type);
	static NAN_METHOD(GenerateRsa);
	static NAN_METHOD(ExportJwk);
	static NAN_METHOD(ExportSpki);
	static NAN_METHOD(ExportPkcs8);
	static NAN_METHOD(ImportJwk);
	static NAN_METHOD(ImportSpki);
	static NAN_METHOD(ImportPkcs8);
	static NAN_METHOD(RsaOaepEncDec);

	static NAN_METHOD(Sign);
	static NAN_METHOD(Verify);

	Handle<ScopedEVP_PKEY> data;

protected:
	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}

};


#endif // OSSL_W_KEY_H_INCLUDE