#ifndef OSSL_NODE_ASYNC_CORE_H_INCLUDE
#define OSSL_NODE_ASYNC_CORE_H_INCLUDE

#include "../core/common.h"

class AsyncDigest: public Nan::AsyncWorker {
public:
	AsyncDigest(
		Nan::Callback *callback,
		Handle<std::string> hDigestName,
		Handle<std::string> hBuffer
		) : AsyncWorker(callback), hDigestName(hDigestName), hBuffer(hBuffer) {}
	~AsyncDigest() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<std::string> hDigestName;
	Handle<std::string> hBuffer;
	// Result
	Handle<std::string> hDigest;
};

#endif // OSSL_NODE_ASYNC_CORE_H_INCLUDE