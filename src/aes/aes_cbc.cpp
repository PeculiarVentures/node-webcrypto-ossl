#include "aes_def.h"

static Handle<std::string> AES_CBC_encrypt(Handle<std::string> hKey, Handle<std::string> hMsg, Handle<std::string> hIv, bool encrypt) {
	LOG_FUNC();

	LOG_INFO("AES key");

	const byte *key = reinterpret_cast<const byte*>(hKey->c_str());
	uint8_t keylen = (uint8_t)hKey->length();

	if (!keylen) {
		THROW_ERROR("Error on AES key getting");
	}

	LOG_INFO("data");
	const byte *data = reinterpret_cast<const byte*> (hMsg->c_str());
	int datalen = (int)hMsg->length();

	LOG_INFO("iv");
	const byte *iv = reinterpret_cast<const byte*>(hIv->c_str());
	uint8_t ivlen = (uint8_t)hIv->length();

	if (ivlen != EVP_MAX_IV_LENGTH) {
		THROW_ERROR("Incorrect IV length");
	}

	// According to the openssl docs, the amount of data written may be as large
	// as (data_size + cipher_block_size - 1), constrained to a multiple of
	// cipher_block_size.
	int output_max_len = AES_BLOCK_SIZE - 1 + datalen;
	if (output_max_len < 0)
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
	default:
		THROW_ERROR("Unknown AES CBC key size");
	}

	ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());

	if (ctx.isEmpty()) {
		THROW_OPENSSL("EVP_CIPHER_CTX_new");
	}

	Handle<std::string> hOutput(new std::string());
	hOutput->resize(output_max_len);
	unsigned char *output = (unsigned char*)hOutput->c_str();

	int output_len = 0;

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
	hOutput->resize(final_output_len);

	return hOutput;
}

Handle<std::string> ScopedAES::encryptCbc(Handle<std::string> hMsg, Handle<std::string> hIv) {
	LOG_FUNC();

	return AES_CBC_encrypt(this->value, hMsg, hIv, true);
}

Handle<std::string> ScopedAES::decryptCbc(Handle<std::string> hMsg, Handle<std::string> hIv) {
	LOG_FUNC();

	return AES_CBC_encrypt(this->value, hMsg, hIv, false);
}

Handle<std::string> ScopedAES::wrap() {
	LOG_FUNC();

	THROW_ERROR("Not implemented");
}

Handle<std::string> ScopedAES::unwrap() {
	LOG_FUNC();

	THROW_ERROR("Not implemented");
}