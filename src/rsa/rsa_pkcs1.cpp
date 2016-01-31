#include "rsa_pkcs1.h"

Handle<ScopedBIO> RSA_PKCS1_sign(Handle<ScopedEVP_PKEY> hKey, const EVP_MD *md, Handle<ScopedBIO> hData) {
	LOG_FUNC();

	ScopedEVP_MD_CTX ctx = EVP_MD_CTX_create();
	EVP_PKEY_CTX* pctx = NULL;  // Owned by |ctx|.
	// NOTE: A call to EVP_DigestSignFinal() with a NULL second parameter
	// returns a maximum allocation size, while the call without a NULL returns
	// the real one, which may be smaller.
	size_t siglen = 0;
	if (ctx.isEmpty() ||
		!EVP_DigestSignInit(ctx.Get(), &pctx, md, NULL, hKey->Get())) {
		THROW_OPENSSL("EVP_DigestSignInit");
	}

	unsigned char* data = NULL;
	unsigned int datalen = BIO_get_mem_data(hData->Get(), &data);

	if (!EVP_DigestSignUpdate(ctx.Get(), data, datalen)) {
		THROW_OPENSSL("EVP_DigestSignUpdate");
	}
	if (!EVP_DigestSignFinal(ctx.Get(), NULL, &siglen)) {
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
	EVP_PKEY_CTX* pctx = NULL;

	if (ctx.isEmpty() ||
		!EVP_DigestVerifyInit(ctx.Get(), &pctx, md, NULL, hKey->Get())) {
		THROW_OPENSSL("EVP_DigestSignInit");
	}

	byte* signature = NULL;
	size_t signaturelen = BIO_get_mem_data(hSignature->Get(), &signature);

	byte* data = NULL;
	size_t datalen = BIO_get_mem_data(hData->Get(), &data);

	if (!EVP_DigestVerifyUpdate(ctx.Get(), data, datalen)) {
		THROW_OPENSSL("EVP_DigestSignUpdate");
	}
	int res = EVP_DigestVerifyFinal(ctx.Get(), signature, signaturelen);

	return res == 1;
}