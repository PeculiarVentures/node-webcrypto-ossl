#ifndef OSSL_NODE_ASYNC_AES_H_INCLUDE
#define OSSL_NODE_ASYNC_AES_H_INCLUDE

#include "../core/common.h"
#include "../aes/common.h"

class AsyncAesGenerateKey : public Nan::AsyncWorker {
public:
	AsyncAesGenerateKey(
		Nan::Callback *callback,
		int keySize
		) : AsyncWorker(callback), keySize(keySize) {}
	~AsyncAesGenerateKey() {}

	void Execute();
	void HandleOKCallback();

protected:
	int keySize;
	// Result
	Handle<ScopedAES> key;
};

class AsyncAesEncryptCBC : public Nan::AsyncWorker {
public:
	AsyncAesEncryptCBC(
		Nan::Callback *callback,
		Handle<ScopedAES> hKey,
		Handle<ScopedBIO> hInput,
		Handle<ScopedBIO> hIv,
		bool encrypt
		) : AsyncWorker(callback), hKey(hKey), hInput(hInput), hIv(hIv), encrypt(encrypt) {}
	~AsyncAesEncryptCBC() {}

	void Execute();
	void HandleOKCallback();

protected:
	bool encrypt;
	Handle<ScopedBIO> hIv;
	Handle<ScopedBIO> hInput;
	Handle<ScopedAES> hKey;
	// Result
	Handle<ScopedBIO> hOutput;
};

#endif // OSSL_NODE_ASYNC_AES_H_INCLUDE