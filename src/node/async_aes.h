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
		Handle<std::string> hInput,
		Handle<std::string> hIv,
		bool encrypt
		) : AsyncWorker(callback), encrypt(encrypt), hIv(hIv), hInput(hInput), hKey(hKey) {}
	~AsyncAesEncryptCBC() {}

	void Execute();
	void HandleOKCallback();

protected:
	bool encrypt;
	Handle<std::string> hIv;
	Handle<std::string> hInput;
	Handle<ScopedAES> hKey;
	// Result
	Handle<std::string> hOutput;
};

class AsyncAesExport : public Nan::AsyncWorker {
public:
	AsyncAesExport(
		Nan::Callback *callback,
		Handle<ScopedAES> hKey
		) : AsyncWorker(callback), hKey(hKey) {}
	~AsyncAesExport() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<ScopedAES> hKey;
	// Result
	Handle<std::string> hOutput;
};

class AsyncAesImport : public Nan::AsyncWorker {
public:
	AsyncAesImport(
		Nan::Callback *callback,
		Handle<std::string> hInput
		) : AsyncWorker(callback), hInput(hInput) {}
	~AsyncAesImport() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<std::string> hInput;
	// Result
	Handle<ScopedAES> hKey;
};

class AsyncAesEncryptGCM : public Nan::AsyncWorker {
public:
	AsyncAesEncryptGCM(
		Nan::Callback *callback,
		Handle<ScopedAES> hKey,
		Handle<std::string> hInput,
		Handle<std::string> hIv,
		Handle<std::string> hAad,
		int tagSize,
		bool encrypt
		) : AsyncWorker(callback), hKey(hKey), hInput(hInput), hIv(hIv), hAad(hAad), tagSize(tagSize), encrypt(encrypt) {}
	~AsyncAesEncryptGCM() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<ScopedAES> hKey;
	Handle<std::string> hInput;
	Handle<std::string> hIv;
	Handle<std::string> hAad;
	int tagSize;
	bool encrypt;
	// Result
	Handle<std::string> hOutput;
};

class AsyncAesWrapKey : public Nan::AsyncWorker {
public:
	AsyncAesWrapKey(
		Nan::Callback *callback,
		Handle<ScopedAES> hKey,
		Handle<std::string> hInput,
		bool encrypt
	) : AsyncWorker(callback), hKey(hKey), hInput(hInput), encrypt(encrypt) {}
	~AsyncAesWrapKey() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<ScopedAES> hKey;
	Handle<std::string> hInput;
	bool encrypt;
	// Result
	Handle<std::string> hOutput;
};

#endif // OSSL_NODE_ASYNC_AES_H_INCLUDE