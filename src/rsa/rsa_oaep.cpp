#include "rsa_oaep.h"

Handle<std::string> RSA_OAEP_enc_dec(
	Handle<ScopedEVP_PKEY> hKey,
	const EVP_MD *md,
	Handle<std::string> hData,
	Handle<std::string> hLabel,
	bool decrypt
	)
{
	LOG_FUNC();

	EVP_PKEY* pKey = hKey->Get();

	ScopedEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(pKey, nullptr));
	if (ctx.isEmpty()) {
		THROW_OPENSSL("EVP_PKEY_CTX_new");
	}

	// EVP_EncryptInit | EVP_DecryptInit
	if (!decrypt) {
		if (EVP_PKEY_encrypt_init(ctx.Get()) < 1) {
			THROW_OPENSSL("EVP_PKEY_encrypt_init");
		}
	}
	else {
		if (EVP_PKEY_decrypt_init(ctx.Get()) < 1) {
			THROW_OPENSSL("EVP_PKEY_decrypt_init");
		}
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx.Get(), RSA_PKCS1_OAEP_PADDING) < 1) {
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_padding");
	}
	if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.Get(), md) < 1) {
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_oaep_md");
	}
	if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.Get(), md) < 1) {
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_mgf1_md");
	}


	if (hLabel->length()) {
		LOG_INFO("Set label for RSA OAEP");
		char *label = (char*)hLabel->c_str();
		int label_len = (int)hLabel->length();
		char *label_copy = (char*)OPENSSL_malloc(label_len);
		memcpy(label_copy, label, label_len);
		if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.Get(), label_copy, label_len) < 1) {
			THROW_OPENSSL("EVP_PKEY_CTX_set0_rsa_oaep_label");
		}
	}

	byte* data = (byte*)hData->c_str();
	size_t datalen = hData->length();

	int(*func_enc_dec)(EVP_PKEY_CTX*,
		byte *, size_t *,
		const byte *, size_t);
	if (!decrypt) {
		LOG_INFO("Set encrypt function");
		func_enc_dec = &EVP_PKEY_encrypt;
	}
	else {
		LOG_INFO("Set deecrypt function");
		func_enc_dec = &EVP_PKEY_decrypt;
	}

	// EVP_PKEY_encrypt | EVP_PKEY_decrypt
	// Determine the maximum length of the output.
	size_t outlen = 0;
	if (func_enc_dec(ctx.Get(), nullptr, &outlen, data, datalen) <= 0) {
		THROW_OPENSSL("func_enc_dec");
	}

	Handle<std::string> hOutput(new std::string());
	hOutput->resize(outlen);
	byte *out = (byte*)hOutput->c_str();


	if (func_enc_dec(ctx.Get(), out, &outlen, data, datalen) <= 0) {
		THROW_OPENSSL("func_enc_dec");
	}

	hOutput->resize(outlen);

	return hOutput;
}