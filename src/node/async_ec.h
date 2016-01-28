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

#endif // OSSL_NODE_ASYNC_EC_H_INCLUDE