#ifndef OSSL_NODE_ASYNC_RSA_H_INCLUDE
#define OSSL_NODE_ASYNC_RSA_H_INCLUDE

#include "../core/common.h"

class ParamsEncrypDecryptRsaOAEP {
public:
	ParamsEncrypDecryptRsaOAEP(
		Handle<ScopedEVP_PKEY> hKey,
		const EVP_MD *md,
		Handle<ScopedBIO> hData,
		Handle<ScopedBIO> hLabel,
		bool decrypt) : hKey(hKey), md(md), hData(hData), hLabel(hLabel), decrypt(decrypt) {}

	Handle<ScopedEVP_PKEY> hKey;
	const EVP_MD *md;
	Handle<ScopedBIO> hData;
	Handle<ScopedBIO> hLabel;
	bool decrypt;
};

template<typename T, typename R>
class AsyncBase : public Nan::AsyncWorker {
public:
	AsyncBase(Nan::Callback *callback, T *params) :AsyncWorker(callback), params(Handle<T>(params)) {}
	~AsyncBase() {}

protected:
	R result;
	Handle<T> params;
};

class AsyncEncrypDecryptRsaOAEP : public AsyncBase<ParamsEncrypDecryptRsaOAEP, Handle<ScopedBIO>> {
public:
	AsyncEncrypDecryptRsaOAEP(Nan::Callback *callback, ParamsEncrypDecryptRsaOAEP *params) :
		AsyncBase(callback, params) {}

	void Execute();
	void HandleOKCallback();
};

#include "common.h"

#endif // OSSL_NODE_ASYNC_RSA_H_INCLUDE