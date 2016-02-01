#include "rsa_pkcs1.h"

Handle<ScopedBIO> RSA_PKCS1_sign(Handle<ScopedEVP_PKEY> hKey, const EVP_MD *md, Handle<ScopedBIO> hData) {
	LOG_FUNC();

	ScopedEVP_MD_CTX ctx = EVP_MD_CTX_create();
	EVP_PKEY_CTX* pctx = nullptr;  

	size_t siglen = 0;
	if (ctx.isEmpty() ||
		!EVP_DigestSignInit(ctx.Get(), &pctx, md, nullptr, hKey->Get())) {
		THROW_OPENSSL("EVP_DigestSignInit");
	}

	unsigned char* data = nullptr;
	unsigned int datalen = BIO_get_mem_data(hData->Get(), &data);

	if (1 != EVP_DigestSignUpdate(ctx.Get(), data, datalen)) {
		THROW_OPENSSL("EVP_DigestSignUpdate");
	}
	if (1 != EVP_DigestSignFinal(ctx.Get(), nullptr, &siglen)) {
		THROW_OPENSSL("EVP_DigestSignFinal");
	}

	byte *output = (byte*)OPENSSL_malloc(siglen);
	Handle<ScopedBIO> hOutput(new ScopedBIO(BIO_new_mem_buf(output, siglen)));

	if (!EVP_DigestSignFinal(ctx.Get(), output, &siglen))
		THROW_OPENSSL("EVP_DigestSignFinal");

	return hOutput;
}

bool RSA_PKCS1_verify(Handle<ScopedEVP_PKEY> hKey, const EVP_MD *md, Handle<ScopedBIO> hData, Handle<ScopedBIO> hSignature) {
	LOG_FUNC();

	ScopedEVP_MD_CTX ctx = EVP_MD_CTX_create();
	EVP_PKEY_CTX* pctx = nullptr;

	if (ctx.isEmpty() ||
		!EVP_DigestVerifyInit(ctx.Get(), &pctx, md, nullptr, hKey->Get())) {
		THROW_OPENSSL("EVP_DigestSignInit");
	}

	byte* signature = nullptr;
	size_t signaturelen = BIO_get_mem_data(hSignature->Get(), &signature);

	byte* data = nullptr;
	size_t datalen = BIO_get_mem_data(hData->Get(), &data);

	if (!EVP_DigestVerifyUpdate(ctx.Get(), data, datalen)) {
		THROW_OPENSSL("EVP_DigestSignUpdate");
	}
	int res = EVP_DigestVerifyFinal(ctx.Get(), signature, signaturelen);

	return res == 1;
}