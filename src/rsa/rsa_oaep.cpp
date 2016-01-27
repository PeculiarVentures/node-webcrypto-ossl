#include "rsa_oaep.h"

Handle<ScopedBIO> RSA_OAEP_enc_dec(
	Handle<ScopedEVP_PKEY> hKey,
	const EVP_MD *md,
	Handle<ScopedBIO> hData,
	Handle<ScopedBIO> hLabel,
	bool decrypt
	)
{
	LOG_FUNC();

	EVP_PKEY* pKey = hKey->Get();

	ScopedEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(pKey, NULL));
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

	if (!hLabel->isEmpty()) {
		LOG_INFO("Set label for RSA OAEP");
		char *label;
		int label_len = BIO_get_mem_data(hLabel->Get(), &label);
		char *label_copy = (char*)OPENSSL_malloc(label_len);
		memcpy(label_copy, label, label_len);
		if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.Get(), label_copy, label_len) < 1) {
			THROW_OPENSSL("EVP_PKEY_CTX_set0_rsa_oaep_label");
		}
	}

	unsigned char* data;
	int datalen = BIO_get_mem_data(hData->Get(), &data);

	int(*func_enc_dec)(EVP_PKEY_CTX*,
		unsigned char *, size_t *,
		const unsigned char *, size_t);
	if (!decrypt) {
		func_enc_dec = &EVP_PKEY_encrypt;
	}
	else {
		func_enc_dec = &EVP_PKEY_decrypt;
	}

	// EVP_PKEY_encrypt | EVP_PKEY_decrypt
	// Determine the maximum length of the output.
	size_t outlen = 0;
	if (func_enc_dec(ctx.Get(), NULL, &outlen, data, datalen) <= 0) {
		THROW_OPENSSL("func_enc_dec");
	}

	byte *out = static_cast<byte*>(OPENSSL_malloc(outlen));

	if (func_enc_dec(ctx.Get(), out, &outlen, data, datalen) <= 0) {
		OPENSSL_free(out);
		THROW_OPENSSL("func_enc_dec");
	}

	//Put result to ScopdBIO	
	Handle<ScopedBIO> res(new ScopedBIO(BIO_new_mem_buf(out, outlen)));
	BIO_set_flags(res->Get(), BIO_CLOSE);

	return res;
}