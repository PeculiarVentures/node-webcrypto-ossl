#ifndef OSSL_NODE_ASYNC_EC_H_INCLUDE
#define OSSL_NODE_ASYNC_EC_H_INCLUDE

#include "../core/common.h"
#include "../ec/common.h"

class AsyncEcGenerateKey : public Nan::AsyncWorker {
public:
	AsyncEcGenerateKey(
		Nan::Callback *callback,
		int namedCurve
		) : AsyncWorker(callback), namedCurve(namedCurve) {}
	~AsyncEcGenerateKey() {}

	void Execute();
	void HandleOKCallback();

protected:
	int namedCurve;
	// Result
	Handle<ScopedEVP_PKEY> key;
};

class AsyncEcdhDeriveKey : public Nan::AsyncWorker {
public:
	AsyncEcdhDeriveKey(
		Nan::Callback *callback,
		Handle<ScopedEVP_PKEY> pkey,
		Handle<ScopedEVP_PKEY> pubkey,
		size_t secret_len
		) : AsyncWorker(callback), pkey(pkey), pubkey(pubkey), secret_len(secret_len) {}
	~AsyncEcdhDeriveKey() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<ScopedEVP_PKEY> pkey;
	Handle<ScopedEVP_PKEY> pubkey;
	size_t secret_len;
	// Result
	Handle<ScopedBIO> dkey;
};

#endif // OSSL_NODE_ASYNC_EC_H_INCLUDE