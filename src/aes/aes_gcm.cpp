#include "aes_def.h"

#include <openssl/aes.h>
#include <openssl/evp.h>

static const EVP_CIPHER* GCM_get_cipher(int keySize) {
	switch (keySize) {
	case 16:
		return EVP_aes_128_gcm();
	case 24:
		return EVP_aes_192_gcm();
	case 32:
		return EVP_aes_256_gcm();
	default:
		THROW_ERROR("Unknown AES GCM key size");
	}
}

static Handle<std::string> AES_GCM_encrypt(
	Handle<std::string> hKey,
	Handle<std::string> hMsg,
	Handle<std::string> hIv,
	Handle<std::string> hAad,
	int tagSize
)
{
	LOG_FUNC();

	const EVP_CIPHER* cipher = GCM_get_cipher((int)hKey->length());
	const byte* iv = (byte*)hIv->c_str();
	const byte* key = (byte*)hKey->c_str();
	const byte* aad = (byte*)hAad->c_str();
	const byte* msg = (byte*)hMsg->c_str();
	byte* output;
	int output_len, final_output_len;
	Handle<std::string> hOutput(new std::string());

	// Get encrypted block size
	int gcm_block_size = EVP_CIPHER_block_size(cipher);
	int max_output_len = gcm_block_size + (int)hMsg->length() + 256;
	if (max_output_len < (int)hMsg->length())
		THROW_ERROR("Input data too large");

	hOutput->resize(max_output_len);
	output = (byte*)hOutput->c_str();

	ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());

	/* Create and initialise the context */
	if (ctx.isEmpty())
		THROW_OPENSSL("EVP_CIPHER_CTX_new");

	/* Initialise the encryption operation. */
	if (1 != EVP_EncryptInit_ex(ctx.Get(), cipher, nullptr, nullptr, nullptr))
		THROW_OPENSSL("Initialise the encryption operation");

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx.Get(), EVP_CTRL_GCM_SET_IVLEN, (int)hIv->length(), nullptr))
		THROW_OPENSSL("EVP_CIPHER_CTX_ctrl");

	/* Initialise key and IV */
	if (1 != EVP_EncryptInit_ex(ctx.Get(), nullptr, nullptr, key, iv))
		THROW_OPENSSL("Initialise key and IV");

	/* Provide any AAD data. This can be called zero or more times as
	* required
	*/
	if (1 != EVP_EncryptUpdate(ctx.Get(), nullptr, &output_len, aad, (int)hAad->length()))
		THROW_OPENSSL("Provide any AAD data");

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_EncryptUpdate(ctx.Get(), output, &output_len, msg, (int)hMsg->length()))
		THROW_OPENSSL("EVP_EncryptUpdate");
	final_output_len = output_len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	* this stage, but this does not occur in GCM mode
	*/
	if (1 != EVP_EncryptFinal_ex(ctx.Get(), output + final_output_len, &output_len))
		THROW_OPENSSL("EVP_EncryptFinal_ex");
	final_output_len += output_len;
	hOutput->resize(final_output_len + tagSize);
	output = (byte*)hOutput->c_str();

	/* Get the tag */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx.Get(), EVP_CTRL_GCM_GET_TAG, tagSize, output + final_output_len))
		THROW_OPENSSL("Get the tag");
	hOutput->resize(final_output_len + tagSize);

	return hOutput;
}

static Handle<std::string> AES_GCM_decrypt(
	Handle<std::string> hKey,
	Handle<std::string> hMsg,
	Handle<std::string> hIv,
	Handle<std::string> hAad,
	int tagSize
)
{
	LOG_FUNC();

	const EVP_CIPHER* cipher = GCM_get_cipher((int)hKey->length());
	const byte* iv = (byte*)hIv->c_str();
	const byte* key = (byte*)hKey->c_str();
	const byte* aad = (byte*)hAad->c_str();
	byte* output;
	int output_len, final_output_len;
	Handle<std::string> hOutput(new std::string());

	int msg_len = (int)hMsg->length() - tagSize;
	std::string sTag = hMsg->substr(hMsg->length() - tagSize);
	hMsg->resize(msg_len);
	const byte* msg = (byte*)hMsg->c_str();

	// Get decrypted block size
	int max_output_len = (int)hMsg->length();
	hOutput->resize(max_output_len);
	output = (byte*)hOutput->c_str();

	ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());

	/* Create and initialise the context */
	if (ctx.isEmpty())
		THROW_OPENSSL("EVP_CIPHER_CTX_new");

	/* Initialise the encryption operation. */
	if (1 != EVP_DecryptInit_ex(ctx.Get(), cipher, nullptr, nullptr, nullptr))
		THROW_OPENSSL("Initialise the encryption operation");

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx.Get(), EVP_CTRL_GCM_SET_IVLEN, (int)hIv->length(), nullptr))
		THROW_OPENSSL("EVP_CIPHER_CTX_ctrl");

	/* Initialise key and IV */
	if (1 != EVP_DecryptInit_ex(ctx.Get(), nullptr, nullptr, key, iv))
		THROW_OPENSSL("Initialise key and IV");

	/* Provide any AAD data. This can be called zero or more times as
	* required
	*/
	if (1 != EVP_DecryptUpdate(ctx.Get(), nullptr, &output_len, aad, (int)hAad->length()))
		THROW_OPENSSL("Provide any AAD data");


	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_DecryptUpdate(ctx.Get(), output, &output_len, msg, (int)hMsg->length()))
		THROW_OPENSSL("EVP_EncryptUpdate");
	final_output_len = output_len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx.Get(), EVP_CTRL_GCM_SET_TAG, tagSize, (byte*)sTag.c_str()))
		THROW_OPENSSL("Set the tag");

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	* this stage, but this does not occur in GCM mode
	*/
	if (1 != EVP_DecryptFinal_ex(ctx.Get(), output + final_output_len, &output_len))
		THROW_OPENSSL("EVP_EncryptFinal_ex");
	final_output_len += output_len;
	hOutput->resize(final_output_len);

	return hOutput;
}

Handle<std::string> ScopedAES::encryptGcm(Handle<std::string> hMsg, Handle<std::string> hIv, Handle<std::string> hAad, int tagSize) {
	LOG_FUNC();

	return AES_GCM_encrypt(this->value, hMsg, hIv, hAad, tagSize);
}

Handle<std::string> ScopedAES::decryptGcm(Handle<std::string> hMsg, Handle<std::string> hIv, Handle<std::string> hAad, int tagSize) {
	LOG_FUNC();

	return AES_GCM_decrypt(this->value, hMsg, hIv, hAad, tagSize);
}