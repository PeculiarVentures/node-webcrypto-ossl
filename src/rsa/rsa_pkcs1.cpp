#include "rsa_pkcs1.h"

Handle<std::string> RSA_PKCS1_sign(Handle<ScopedEVP_PKEY> hKey, const EVP_MD *md, Handle<std::string> hData) {
	LOG_FUNC();

	ScopedEVP_MD_CTX ctx(EVP_MD_CTX_create());
	EVP_PKEY_CTX* pctx = nullptr;

	size_t siglen = 0;
	if (ctx.isEmpty() ||
		!EVP_DigestSignInit(ctx.Get(), &pctx, md, nullptr, hKey->Get())) {
		THROW_OPENSSL("EVP_DigestSignInit");
	}

	byte* data = (byte*)hData->c_str();
	size_t datalen = hData->length();

	if (1 != EVP_DigestSignUpdate(ctx.Get(), data, datalen)) {
		THROW_OPENSSL("EVP_DigestSignUpdate");
	}
	if (1 != EVP_DigestSignFinal(ctx.Get(), nullptr, &siglen)) {
		THROW_OPENSSL("EVP_DigestSignFinal");
	}

	Handle<std::string> hOutput(new std::string());
	hOutput->resize(siglen);
	byte *output = (byte*)hOutput->c_str();

	if (!EVP_DigestSignFinal(ctx.Get(), output, &siglen))
		THROW_OPENSSL("EVP_DigestSignFinal");

	return hOutput;
}

bool RSA_PKCS1_verify(Handle<ScopedEVP_PKEY> hKey, const EVP_MD *md, Handle<std::string> hData, Handle<std::string> hSignature) {
	LOG_FUNC();

	ScopedEVP_MD_CTX ctx(EVP_MD_CTX_create());
	EVP_PKEY_CTX* pctx = nullptr;

	if (ctx.isEmpty() ||
		!EVP_DigestVerifyInit(ctx.Get(), &pctx, md, nullptr, hKey->Get())) {
		THROW_OPENSSL("EVP_DigestSignInit");
	}

	byte* signature = (byte*)hSignature->c_str();
	size_t signaturelen = hSignature->length();

	byte* data = (byte*)hData->c_str();
	size_t datalen = hData->length();

	if (!EVP_DigestVerifyUpdate(ctx.Get(), data, datalen)) {
		THROW_OPENSSL("EVP_DigestSignUpdate");
	}
	int res = EVP_DigestVerifyFinal(ctx.Get(), signature, signaturelen);

	return res == 1;
}