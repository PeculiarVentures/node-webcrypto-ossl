#ifndef OSSL_NODE_ASYNC_RSA_H_INCLUDE
#define OSSL_NODE_ASYNC_RSA_H_INCLUDE

#include "../core/common.h"
#include "../rsa/common.h"

class AsyncRsaGenerateKey : public Nan::AsyncWorker {
public:
	AsyncRsaGenerateKey(
		Nan::Callback *callback,
		int modulusBits,
		int publicExponent
		) : AsyncWorker(callback), modulusBits(modulusBits), publicExponent(publicExponent) {}
	~AsyncRsaGenerateKey() {}

	void Execute();
	void HandleOKCallback();

protected:
	int modulusBits;
	int publicExponent;
	// Result
	Handle<ScopedEVP_PKEY> key;
};

class AsyncEncrypDecryptRsaOAEP : public Nan::AsyncWorker {
public:
	AsyncEncrypDecryptRsaOAEP(
		Nan::Callback *callback,
		Handle<ScopedEVP_PKEY> hKey,
		const EVP_MD *md,
		Handle<ScopedBIO> hData,
		Handle<ScopedBIO> hLabel,
		bool decrypt
		) : AsyncWorker(callback), hKey(hKey), md(md), hData(hData), hLabel(hLabel), decrypt(decrypt) {}

	void Execute();
	void HandleOKCallback();
protected:
	Handle<ScopedEVP_PKEY> hKey;
	const EVP_MD *md;
	Handle<ScopedBIO> hData;
	Handle<ScopedBIO> hLabel;
	bool decrypt;
	// Result
	Handle<ScopedBIO> hResult;
};

class AsyncExportJwkRsa : public Nan::AsyncWorker {
public:
	AsyncExportJwkRsa(
		Nan::Callback *callback,
		int key_type,
		Handle<ScopedEVP_PKEY> key)
		: AsyncWorker(callback), key_type(key_type), key(key) {}
	~AsyncExportJwkRsa() {}

	void Execute();
	void HandleOKCallback();

protected:
	int key_type;
	Handle<ScopedEVP_PKEY> key;
	// Result
	Handle<JwkRsa> jwk;
};

class AsyncExportSpki : public Nan::AsyncWorker {
public:
	AsyncExportSpki(
		Nan::Callback *callback,
		Handle<ScopedEVP_PKEY>key)
		: AsyncWorker(callback), key(key) {}
	~AsyncExportSpki() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<ScopedEVP_PKEY> key;
	// Result
	Handle<ScopedBIO> buffer;
};

class AsyncExportPkcs8 : public Nan::AsyncWorker {
public:
	AsyncExportPkcs8(
		Nan::Callback *callback,
		Handle<ScopedEVP_PKEY>key)
		: AsyncWorker(callback), key(key) {}
	~AsyncExportPkcs8() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<ScopedEVP_PKEY> key;
	// Result
	Handle<ScopedBIO> buffer;
};

class AsyncImportPkcs8 : public Nan::AsyncWorker {
public:
	AsyncImportPkcs8(
		Nan::Callback *callback,
		Handle<ScopedBIO> in)
		: AsyncWorker(callback), in(in) {}
	~AsyncImportPkcs8() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<ScopedBIO> in;
	// Result
	Handle<ScopedEVP_PKEY> key;
};

class AsyncImportSpki : public Nan::AsyncWorker {
public:
	AsyncImportSpki(
		Nan::Callback *callback,
		Handle<ScopedBIO> in)
		: AsyncWorker(callback), in(in) {}
	~AsyncImportSpki() {}

	void Execute();
	void HandleOKCallback();

private:
	Handle<ScopedBIO> in;
	// Result
	Handle<ScopedEVP_PKEY> key;
};

class AsyncImportJwkRsa : public Nan::AsyncWorker {
public:
	AsyncImportJwkRsa(Nan::Callback *callback, Handle<JwkRsa> jwk, int key_type)
		: AsyncWorker(callback), jwk(jwk), key_type(key_type) {}
	~AsyncImportJwkRsa() {}

	void Execute();
	void HandleOKCallback();

protected:
	int key_type;
	Handle<JwkRsa> jwk;
	//Result
	Handle<ScopedEVP_PKEY> pkey;
};

class AsyncSignRsa : public Nan::AsyncWorker {
public:
	AsyncSignRsa(
		Nan::Callback *callback,
		const EVP_MD *md,
		Handle<ScopedEVP_PKEY> pkey,
		Handle<ScopedBIO> in)
		: AsyncWorker(callback), md(md), pkey(pkey), in(in) {}
	~AsyncSignRsa() {}

	void Execute();
	void HandleOKCallback();

private:
	const EVP_MD *md;
	Handle<ScopedEVP_PKEY> pkey;
	Handle<ScopedBIO> in;
	//Result
	Handle<ScopedBIO> out;
};

class AsyncVerifyRsa : public Nan::AsyncWorker {
public:
	AsyncVerifyRsa(
		Nan::Callback *callback,
		const EVP_MD *md,
		Handle<ScopedEVP_PKEY> pkey,
		Handle<ScopedBIO> in,
		Handle<ScopedBIO> signature)
		: AsyncWorker(callback), md(md), pkey(pkey), in(in), signature(signature) {}
	~AsyncVerifyRsa() {}

	void Execute();
	void HandleOKCallback();

private:
	const EVP_MD *md;
	Handle<ScopedEVP_PKEY> pkey;
	Handle<ScopedBIO> in;
	Handle<ScopedBIO> signature;
	// Result
	bool res;
};

#include "common.h"

#endif // OSSL_NODE_ASYNC_RSA_H_INCLUDE