#include "ec_dsa.h"

/* constant_time_select_ulong returns |x| if |v| is 1 and |y| if |v| is 0. Its
* behavior is undefined if |v| takes any other value. */
static BN_ULONG constant_time_select_ulong(int v, BN_ULONG x, BN_ULONG y) {
	BN_ULONG mask = v;
	mask--;
	return (~mask & x) | (mask & y);
}

/* constant_time_le_size_t returns 1 if |x| <= |y| and 0 otherwise. |x| and |y|
* must not have their MSBs set. */
static int constant_time_le_size_t(size_t x, size_t y) {
	return ((x - y - 1) >> (sizeof(size_t) * 8 - 1)) & 1;
}

/* read_word_padded returns the |i|'th word of |in|, if it is not out of
* bounds. Otherwise, it returns 0. It does so without branches on the size of
* |in|, however it necessarily does not have the same memory access pattern. If
* the access would be out of bounds, it reads the last word of |in|. |in| must
* not be zero. */
static BN_ULONG read_word_padded(const BIGNUM *in, size_t i) {
	/* Read |in->d[i]| if valid. Otherwise, read the last word. */
	BN_ULONG l = in->d[constant_time_select_ulong(
		constant_time_le_size_t(in->dmax, i), in->dmax - 1, i)];
	/* Clamp to zero if above |d->top|. */
	return constant_time_select_ulong(constant_time_le_size_t(in->top, i), 0, l);
}

static int BN_bn2bin_padded(uint8_t *out, size_t len, const BIGNUM *in) {
	size_t i;
	BN_ULONG l;
	/* Special case for |in| = 0. Just branch as the probability is negligible. */
	if (BN_is_zero(in)) {
		memset(out, 0, len);
		return 1;
	}
	/* Check if the integer is too big. This case can exit early in non-constant
	* time. */
	if ((size_t)in->top > (len + (BN_BYTES - 1)) / BN_BYTES) {
		return 0;
	}
	if ((len % BN_BYTES) != 0) {
		l = read_word_padded(in, len / BN_BYTES);
		if (l >> (8 * (len % BN_BYTES)) != 0) {
			return 0;
		}
	}
	/* Write the bytes out one by one. Serialization is done without branching on
	* the bits of |in| or on |in->top|, but if the routine would otherwise read
	* out of bounds, the memory access pattern can't be fixed. However, for an
	* RSA key of size a multiple of the word size, the probability of BN_BYTES
	* leading zero octets is low.
	*
	* See Falko Stenzke, "Manger's Attack revisited", ICICS 2010. */
	i = len;
	while (i--) {
		l = read_word_padded(in, i / BN_BYTES);
		*(out++) = (uint8_t)(l >> (8 * (i % BN_BYTES))) & 0xff;
	}
	return 1;
}

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
	size_t order_size_bytes = GetEcGroupOrderSize(key);

	// If the size of the signature is incorrect, verification must fail. Success
	// is returned here rather than an error, so that the caller can fail
	// verification with a boolean, rather than reject the promise with an
	// exception.
	if (signaturelen != 2 * order_size_bytes) {
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