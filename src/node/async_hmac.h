#ifndef OSSL_NODE_ASYNC_HMAC_H_INCLUDE
#define OSSL_NODE_ASYNC_HMAC_H_INCLUDE

#include "../core/common.h"
#include "../hmac/common.h"

class AsyncHmacGenerateKey : public Nan::AsyncWorker {
public:
	AsyncHmacGenerateKey(
		Nan::Callback *callback,
		int keySize
		) : AsyncWorker(callback), keySize(keySize) {}
	~AsyncHmacGenerateKey() {}

	void Execute();
	void HandleOKCallback();

protected:
	int keySize;
	// Result
	Handle<ScopedHMAC> key;
};

class AsyncHmacExport : public Nan::AsyncWorker {
public:
	AsyncHmacExport(
		Nan::Callback *callback,
		Handle<ScopedHMAC> hKey
		) : AsyncWorker(callback), hKey(hKey) {}
	~AsyncHmacExport() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<ScopedHMAC> hKey;
	// Result
	Handle<std::string> hOutput;
};

class AsyncHmacImport : public Nan::AsyncWorker {
public:
	AsyncHmacImport(
		Nan::Callback *callback,
		Handle<std::string> hInput
		) : AsyncWorker(callback), hInput(hInput) {}
	~AsyncHmacImport() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<std::string> hInput;
	// Result
	Handle<ScopedHMAC> hKey;
};

class AsyncHmacSign : public Nan::AsyncWorker {
public:
	AsyncHmacSign(
		Nan::Callback *callback,
		const EVP_MD *md,
		Handle<ScopedHMAC> pkey,
		Handle<std::string> in)
		: AsyncWorker(callback), md(md), pkey(pkey), in(in) {}
	~AsyncHmacSign() {}

	void Execute();
	void HandleOKCallback();

private:
	const EVP_MD *md;
	Handle<ScopedHMAC> pkey;
	Handle<std::string> in;
	//Result
	Handle<std::string> out;
};

class AsyncHmacVerify : public Nan::AsyncWorker {
public:
	AsyncHmacVerify(
		Nan::Callback *callback,
		const EVP_MD *md,
		Handle<ScopedHMAC> pkey,
		Handle<std::string> in,
		Handle<std::string> signature)
		: AsyncWorker(callback), md(md), pkey(pkey), in(in), signature(signature) {}
	~AsyncHmacVerify() {}

	void Execute();
	void HandleOKCallback();

private:
	const EVP_MD *md;
	Handle<ScopedHMAC> pkey;
	Handle<std::string> in;
	Handle<std::string> signature;
	// Result
	bool res;
};

#endif // OSSL_NODE_ASYNC_HMAC_H_INCLUDE