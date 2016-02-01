#include "aes_def.h"

Handle<ScopedBIO> AES_CBC_encrypt(Handle<ScopedAES> hKey, Handle<ScopedBIO> hMsg, Handle<ScopedBIO> hIv, bool encrypt) {
	LOG_FUNC();

	LOG_INFO("AES key");
	byte *key;
	uint8_t keylen = BIO_get_mem_data(hKey->value->Get(), &key);

	if (!keylen) {
		THROW_ERROR("Error on AES key getting");
	}

	LOG_INFO("data");
	byte *data;
	uint8_t datalen = BIO_get_mem_data(hMsg->Get(), &data);

	LOG_INFO("data");
	byte *iv;
	uint8_t ivlen = BIO_get_mem_data(hIv->Get(), &iv);

	if (ivlen != EVP_MAX_IV_LENGTH) {
		THROW_ERROR("Incorrect IV length");
	}

	// According to the openssl docs, the amount of data written may be as large
	// as (data_size + cipher_block_size - 1), constrained to a multiple of
	// cipher_block_size.
	int output_max_len = datalen;
	output_max_len += AES_BLOCK_SIZE - 1;
	if (output_max_len < datalen)
		THROW_ERROR("Input data too large");

	const unsigned remainder = output_max_len % AES_BLOCK_SIZE;
	if (remainder != 0)
		output_max_len += AES_BLOCK_SIZE - remainder;
	if (output_max_len < datalen)
		THROW_ERROR("Input data too large");

	LOG_INFO("Get AES cipher by key size");
	const EVP_CIPHER *cipher;
	switch (keylen) {
	case 16:
		cipher = EVP_aes_128_cbc();
		break;
	case 24:
		cipher = EVP_aes_192_cbc();
		break;
	case 32:
		cipher = EVP_aes_256_cbc();
		break;
	}

	ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
    
	if (ctx.isEmpty()) {
		THROW_OPENSSL("EVP_CIPHER_CTX_new");
	}

	byte* output = (byte*)OPENSSL_malloc(output_max_len);
	int output_len = 0;
	ScopedBIO hOut(BIO_new_mem_buf(output, output_max_len));

	if (1 != EVP_CipherInit_ex(ctx.Get(), cipher, nullptr, key, iv, encrypt)) {
		THROW_OPENSSL("EVP_CipherInit_ex");
	}
	if (1 != EVP_CipherUpdate(ctx.Get(), output, &output_len, data, datalen)) {
		THROW_OPENSSL("EVP_CipherInit_ex");
	}

	int final_output_chunk_len = 0;
	if (1 != EVP_CipherFinal_ex(ctx.Get(), output + output_len, &final_output_chunk_len)) {
		THROW_OPENSSL("EVP_CipherFinal_ex");
	}

	const unsigned int final_output_len =
		static_cast<unsigned int>(output_len) +
		static_cast<unsigned int>(final_output_chunk_len);

	LOG_INFO("Resize output");
	//TODO: optimize resize
	byte *res = (byte*)OPENSSL_malloc(final_output_len);
	memcpy(res, output, final_output_len);
	Handle<ScopedBIO> hResult(new ScopedBIO(BIO_new_mem_buf(res, final_output_len)));

	return hResult;
}

Handle<ScopedBIO> ScopedAES::encrypt(Handle<ScopedAES> hKey, Handle<ScopedBIO> hMsg, Handle<ScopedBIO> hIv) {
	LOG_FUNC();

	return AES_CBC_encrypt(hKey, hMsg, hIv, true);
}

Handle<ScopedBIO> ScopedAES::decrypt(Handle<ScopedAES> hKey, Handle<ScopedBIO> hMsg, Handle<ScopedBIO> hIv) {
	LOG_FUNC();

	return AES_CBC_encrypt(hKey, hMsg, hIv, false);
}

Handle<ScopedBIO> ScopedAES::wrap() {
	LOG_FUNC();

	THROW_ERROR("Not implemented");
}

Handle<ScopedBIO> ScopedAES::unwrap() {
	LOG_FUNC();

	THROW_ERROR("Not implemented");
}