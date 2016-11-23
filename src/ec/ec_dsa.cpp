#include "ec_dsa.h"

static size_t GetEcGroupOrderSize(EVP_PKEY* pkey) {
	LOG_FUNC();

	if (!pkey)
		THROW_ERROR("GetEcGroupOrderSize: Key is nullptr");

	EC_KEY *ec = pkey->pkey.ec;
	if (!ec)
		THROW_ERROR("GetEcGroupOrderSize: Key is not EC");

	const EC_GROUP* group = EC_KEY_get0_group(ec);
	ScopedBIGNUM order(BN_new());
	if (!EC_GROUP_get_order(group, order.Get(), nullptr)) {
		THROW_OPENSSL("GetEcGroupOrderSize: EC_GROUP_get_order");
	}
	size_t res = BN_num_bytes(order.Get());

	return res;
}

static Handle<std::string> ConvertWebCryptoSignatureToDerSignature(
	EVP_PKEY* key,
	const byte *signature,
	const size_t &signaturelen,
	bool* incorrect_length)
{
	LOG_FUNC();

	LOG_INFO("Determine the length of r and s");
	int order_size_bytes = (int)GetEcGroupOrderSize(key);

	// If the size of the signature is incorrect, verification must fail. Success
	// is returned here rather than an error, so that the caller can fail
	// verification with a boolean, rather than reject the promise with an
	// exception.
	if (signaturelen != 2 * (size_t)order_size_bytes) {
		*incorrect_length = true;
		return nullptr;
	}
	*incorrect_length = false;
	LOG_INFO("Construct an ECDSA_SIG from |signature|");
	ScopedECDSA_SIG ecdsa_sig(ECDSA_SIG_new());

	if (ecdsa_sig.isEmpty())
		THROW_OPENSSL("ConvertWebCryptoSignatureToDerSignature: ECDSA_SIG_new");

	if (!BN_bin2bn(signature, order_size_bytes, ecdsa_sig.Get()->r) ||
		!BN_bin2bn(signature + order_size_bytes, order_size_bytes,
			ecdsa_sig.Get()->s)) {
		THROW_OPENSSL("ConvertWebCryptoSignatureToDerSignature: BN_bin2bn");
	}

	LOG_INFO("DER-encode the signature");
	byte* der = nullptr;
	uint32_t derlen;
	derlen = i2d_ECDSA_SIG(ecdsa_sig.Get(), &der);
	if (derlen <= 0) {
		THROW_OPENSSL("ConvertWebCryptoSignatureToDerSignature: i2d_ECDSA_SIG");
	}
	Handle<std::string> hSignature(new std::string((char *)der, derlen));

	OPENSSL_free(der);

	return hSignature;
}

// Formats a DER-encoded signature (ECDSA-Sig-Value as specified in RFC 3279) to
// the signature format expected by WebCrypto (raw concatenated "r" and "s").
static Handle<std::string> ConvertDerSignatureToWebCryptoSignature(
	EVP_PKEY* key,
	const byte* signature,
	size_t &signaturelen)
{
	LOG_FUNC();

	ScopedECDSA_SIG ecdsa_sig(d2i_ECDSA_SIG(nullptr, &signature, static_cast<long>(signaturelen)));
	if (ecdsa_sig.isEmpty())
		THROW_OPENSSL("d2i_ECDSA_SIG");

	// Determine the maximum length of r and s.
	size_t order_size_bytes = GetEcGroupOrderSize(key);

	Handle<std::string> hSignature(new std::string());
	hSignature->resize(order_size_bytes * 2);
	byte *pSignature = (byte*)hSignature->c_str();

	if (!BN_bn2bin_padded(pSignature, order_size_bytes, ecdsa_sig.Get()->r)) {
		THROW_OPENSSL("BN_bn2bin_padded");
	}
	if (!BN_bn2bin_padded(pSignature + order_size_bytes, order_size_bytes, ecdsa_sig.Get()->s)) {
		THROW_OPENSSL("BN_bn2bin_padded");
	}

	return hSignature;
}

Handle<std::string> EC_DSA_sign(Handle<ScopedEVP_PKEY> hKey, const EVP_MD *md, Handle<std::string> hData) {
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

	if (!EVP_DigestSignUpdate(ctx.Get(), data, datalen)) {
		THROW_OPENSSL("EVP_DigestSignUpdate");
	}
	if (!EVP_DigestSignFinal(ctx.Get(), nullptr, &siglen)) {
		THROW_OPENSSL("EVP_DigestSignFinal");
	}

	Handle<std::string> hSignature(new std::string());
	hSignature->resize(siglen);
	byte *sig = (byte*)hSignature->c_str();

	if (!EVP_DigestSignFinal(ctx.Get(), sig, &siglen))
		THROW_OPENSSL("EVP_DigestSignFinal");

	// NOTE: A call to EVP_DigestSignFinal() with a NULL second parameter
	// returns a maximum allocation size, while the call without a NULL returns
	// the real one, which may be smaller.
	hSignature->resize(siglen);
	sig = (byte*)hSignature->c_str();

	Handle<std::string> hWcSignature = ConvertDerSignatureToWebCryptoSignature(hKey->Get(), sig, siglen);

	return hWcSignature;
}

bool EC_DSA_verify(Handle<ScopedEVP_PKEY> hKey, const EVP_MD *md, Handle<std::string> hData, Handle<std::string> hSignature) {
	LOG_FUNC();

	byte* pWcSignature = (byte*)hSignature->c_str();
	size_t wcSignatureLen = hSignature->length();

	bool incorrect;
	Handle<std::string> hFormatedSignature = ConvertWebCryptoSignatureToDerSignature(hKey->Get(), pWcSignature, wcSignatureLen, &incorrect);

	if (incorrect) {
		LOG_INFO("Incorrect signature value");
		return false;
	}

	ScopedEVP_MD_CTX ctx(EVP_MD_CTX_create());
	EVP_PKEY_CTX* pctx = nullptr;

	if (ctx.isEmpty() ||
		!EVP_DigestVerifyInit(ctx.Get(), &pctx, md, nullptr, hKey->Get())) {
		THROW_OPENSSL("EVP_DigestSignInit");
	}

	byte* signature = (byte*)hFormatedSignature->c_str();
	size_t signaturelen = hFormatedSignature->length();

	byte* data = (byte*)hData->c_str();
	size_t datalen = hData->length();

	if (!EVP_DigestVerifyUpdate(ctx.Get(), data, datalen)) {
		THROW_OPENSSL("EVP_DigestSignUpdate");
	}
	int res = EVP_DigestVerifyFinal(ctx.Get(), signature, signaturelen);

	return res == 1;
}