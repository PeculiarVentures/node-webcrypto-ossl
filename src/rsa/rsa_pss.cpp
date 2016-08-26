#include "rsa_pss.h"

static void setRsaPssParams(const EVP_MD *md, int saltLen, EVP_PKEY_CTX* pctx) {
	LOG_FUNC();

	if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) ||
		1 != EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) ||
		1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(
			pctx, saltLen)) {
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa...");
	}
}

Handle<std::string> RSA_PSS_sign(Handle<ScopedEVP_PKEY> hKey, const EVP_MD *md, int saltLen, Handle<std::string> hData) {
	LOG_FUNC();

	ScopedEVP_MD_CTX ctx(EVP_MD_CTX_create());
	EVP_PKEY_CTX* pctx = nullptr;

	size_t siglen = 0;
	if (ctx.isEmpty() ||
		!EVP_DigestSignInit(ctx.Get(), &pctx, md, nullptr, hKey->Get())) {
		THROW_OPENSSL("EVP_DigestSignInit");
	}

	setRsaPssParams(md, saltLen, pctx);

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

bool RSA_PSS_verify(Handle<ScopedEVP_PKEY> hKey, const EVP_MD *md, int saltLen, Handle<std::string> hData, Handle<std::string> hSignature) {
	LOG_FUNC();

	ScopedEVP_MD_CTX ctx(EVP_MD_CTX_create());
	EVP_PKEY_CTX* pctx = nullptr;

	if (ctx.isEmpty() ||
		!EVP_DigestVerifyInit(ctx.Get(), &pctx, md, nullptr, hKey->Get())) {
		THROW_OPENSSL("EVP_DigestSignInit");
	}

	setRsaPssParams(md, saltLen, pctx);

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