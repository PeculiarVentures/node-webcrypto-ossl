#include "common.h"

Handle<std::string> ScopedPbkdf2::deriveBits(Handle<std::string> salt, size_t iterations, const EVP_MD *md, size_t deriv_bits_length) {
	LOG_FUNC();

	if (!deriv_bits_length)
		THROW_ERROR("PKKDF2: Derive bits length not specified");

	if (deriv_bits_length % 8)
		THROW_ERROR("PKKDF2: Derive bits length not a multiple of 8 bytes");

	if (!iterations)
		THROW_ERROR("PKKDF2: Iterations can't be 0");

	if (!md)
		THROW_ERROR("PKKDF2: Message digest agorithm is empty");

	Handle<std::string> res(new std::string());
	res->resize(deriv_bits_length / 8);

	if (!PKCS5_PBKDF2_HMAC(
		this->value->c_str(), this->value->length(),
		(const byte*)salt->c_str(), salt->length(),
		iterations, md,
		(int)(deriv_bits_length / 8), (byte*)res->c_str())
		) {
		THROW_OPENSSL("PKCS5_PBKDF2_HMAC");
	}

	return res;
}