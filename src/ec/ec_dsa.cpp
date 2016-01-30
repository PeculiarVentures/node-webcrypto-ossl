#include "ec_dsa.h"

static size_t GetEcGroupOrderSize(EVP_PKEY* pkey) {
	LOG_FUNC();

	if (!pkey)
		THROW_ERROR("GetEcGroupOrderSize: Key is NULL");

	EC_KEY *ec = pkey->pkey.ec;
	if (!ec)
		THROW_ERROR("GetEcGroupOrderSize: Key is not EC");

	const EC_GROUP* group = EC_KEY_get0_group(ec);
	ScopedBIGNUM order = BN_new();
	if (!EC_GROUP_get_order(group, order.Get(), NULL)) {
		THROW_OPENSSL("GetEcGroupOrderSize: EC_GROUP_get_order");
	}
	size_t res = BN_num_bytes(order.Get());

	return res;
}

static Handle<ScopedBIO> ConvertWebCryptoSignatureToDerSignature(
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
		return NULL;
	}
	*incorrect_length = false;
	LOG_INFO("Construct an ECDSA_SIG from |signature|");
	ScopedECDSA_SIG ecdsa_sig = ECDSA_SIG_new();

	if (ecdsa_sig.isEmpty())
		THROW_OPENSSL("ConvertWebCryptoSignatureToDerSignature: ECDSA_SIG_new");

	if (!BN_bin2bn(signature, order_size_bytes, ecdsa_sig.Get()->r) ||
		!BN_bin2bn(signature + order_size_bytes, order_size_bytes,
			ecdsa_sig.Get()->s)) {
		THROW_OPENSSL("ConvertWebCryptoSignatureToDerSignature: BN_bin2bn");
	}

	LOG_INFO("DER-encode the signature");
	byte* der = NULL;
	uint32_t derlen;
	derlen = i2d_ECDSA_SIG(ecdsa_sig.Get(), &der);
	if (der <= 0) {
		THROW_OPENSSL("ConvertWebCryptoSignatureToDerSignature: i2d_ECDSA_SIG");
	}
	Handle<ScopedBIO> hSignature(new ScopedBIO(BIO_new_mem_buf(der, derlen)));
	return hSignature;
}

// Formats a DER-encoded signature (ECDSA-Sig-Value as specified in RFC 3279) to
// the signature format expected by WebCrypto (raw concatenated "r" and "s").
static Handle<ScopedBIO> ConvertDerSignatureToWebCryptoSignature(
	EVP_PKEY* key,
	const byte* signature,
	uint32_t &signaturelen) 
{
	LOG_FUNC();

	ScopedECDSA_SIG ecdsa_sig = d2i_ECDSA_SIG(NULL, &signature, static_cast<long>(signaturelen));
	if (ecdsa_sig.isEmpty())
		THROW_OPENSSL("d2i_ECDSA_SIG");
	
	// Determine the maximum length of r and s.
	size_t order_size_bytes = GetEcGroupOrderSize(key);

	int signaturelen_ = order_size_bytes * 2;
	byte *signature_ = (byte*)OPENSSL_malloc(signaturelen_);
	Handle<ScopedBIO> hSignature(new ScopedBIO(BIO_new_mem_buf(signature_, signaturelen_)));

	if (!BN_bn2bin(ecdsa_sig.Get()->r, signature_)) {
		THROW_OPENSSL("BN_bin2bn");
	}
	if (!BN_bn2bin(ecdsa_sig.Get()->s, signature_ + order_size_bytes)) { // padding pointer
		THROW_OPENSSL("BN_bin2bn");
	}

	return hSignature;
}

Handle<ScopedBIO> EC_DSA_sign(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in) {
	LOG_FUNC();

	ScopedEC_KEY ec = EVP_PKEY_get1_EC_KEY(key->Get());
	if (ec.isEmpty()) {
		THROW_OPENSSL("EVP_PKEY_get1_EC_KEY");
	}

	byte sig[2048] = { 0 };
	uint32_t siglen = 0;

	byte* buf = NULL;
	size_t buflen = BIO_get_mem_data(in->Get(), &buf);

	if (ECDSA_sign(md->type, buf, buflen, sig, &siglen, ec.Get()) < 1) {
		THROW_OPENSSL("ECDSA_sign");
	}

	Handle<ScopedBIO> hSignature = ConvertDerSignatureToWebCryptoSignature(key->Get(), sig, siglen);

	return hSignature;
}

bool EC_DSA_verify(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in, Handle<ScopedBIO> signature) {
	LOG_FUNC();

	unsigned char* wcSignature = NULL;
	unsigned int wcSignatureLen = BIO_get_mem_data(signature->Get(), &wcSignature);

	bool incorrect;
	Handle<ScopedBIO> hSignature = ConvertWebCryptoSignatureToDerSignature(key->Get(), wcSignature, wcSignatureLen, &incorrect);

	if (incorrect) {
		LOG_INFO("Incorrect signature value");
		return false;
	}

	ScopedEC_KEY ec = EVP_PKEY_get1_EC_KEY(key->Get());
	if (ec.isEmpty()) {
		THROW_OPENSSL("EVP_PKEY_get1_EC_KEY");
	}

	LOG_INFO("prepare data");
	unsigned char* data = NULL;
	unsigned int datalen = BIO_get_mem_data(in->Get(), &data);

	LOG_INFO("prepare signature");
	unsigned char* sig = NULL;
	unsigned int siglen = BIO_get_mem_data(hSignature->Get(), &sig);

	int res = ECDSA_verify(md->type, data, datalen, sig, siglen, ec.Get());
	if (res == -1) {
		THROW_OPENSSL("ECDSA_verify");
	}

	return res == 1;
}