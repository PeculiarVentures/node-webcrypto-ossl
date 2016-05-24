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
	Handle<std::string> dkey;
};

class AsyncEcExportJwk : public Nan::AsyncWorker {
public:
	AsyncEcExportJwk(
		Nan::Callback *callback,
		int key_type,
		Handle<ScopedEVP_PKEY> key)
		: AsyncWorker(callback), key_type(key_type), key(key) {}
	~AsyncEcExportJwk() {}

	void Execute();
	void HandleOKCallback();

protected:
	int key_type;
	Handle<ScopedEVP_PKEY> key;
	// Result
	Handle<JwkEc> jwk;
};

class AsyncEcImportJwk : public Nan::AsyncWorker {
public:
	AsyncEcImportJwk(Nan::Callback *callback, Handle<JwkEc> jwk, int key_type)
		: AsyncWorker(callback), jwk(jwk), key_type(key_type) {}
	~AsyncEcImportJwk() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<JwkEc> jwk;
	int key_type;
	//Result
	Handle<ScopedEVP_PKEY> pkey;
};

class AsyncEcdsaSign : public Nan::AsyncWorker {
public:
	AsyncEcdsaSign(
		Nan::Callback *callback,
		const EVP_MD *md,
		Handle<ScopedEVP_PKEY> pkey,
		Handle<std::string> in)
		: AsyncWorker(callback), md(md), pkey(pkey), in(in) {}
	~AsyncEcdsaSign() {}

	void Execute();
	void HandleOKCallback();

private:
	const EVP_MD *md;
	Handle<ScopedEVP_PKEY> pkey;
	Handle<std::string> in;
	//Result
	Handle<std::string> out;
};

class AsyncEcdsaVerify : public Nan::AsyncWorker {
public:
	AsyncEcdsaVerify(
		Nan::Callback *callback,
		const EVP_MD *md,
		Handle<ScopedEVP_PKEY> pkey,
		Handle<std::string> in,
		Handle<std::string> signature)
		: AsyncWorker(callback), md(md), pkey(pkey), in(in), signature(signature) {}
	~AsyncEcdsaVerify() {}

	void Execute();
	void HandleOKCallback();

private:
	const EVP_MD *md;
	Handle<ScopedEVP_PKEY> pkey;
	Handle<std::string> in;
	Handle<std::string> signature;
	// Result
	bool res;
};

class AsyncEcdhDeriveBits : public Nan::AsyncWorker {
public:
	AsyncEcdhDeriveBits(
		Nan::Callback *callback,
		Handle<ScopedEVP_PKEY> pkey,
		Handle<ScopedEVP_PKEY> pubkey,
		size_t length_bits
	) : AsyncWorker(callback), pkey(pkey), pubkey(pubkey), length_bits(length_bits) {}
	~AsyncEcdhDeriveBits() {}

	void Execute();
	void HandleOKCallback();

protected:
	Handle<ScopedEVP_PKEY> pkey;
	Handle<ScopedEVP_PKEY> pubkey;
	size_t length_bits;
	// Result
	Handle<std::string> dbits;
};

#endif // OSSL_NODE_ASYNC_EC_H_INCLUDE