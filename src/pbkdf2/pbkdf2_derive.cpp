#include "common.h"

Handle<std::string> ScopedPbkdf2::deriveBits(Handle<std::string> salt, size_t iterations, const EVP_MD *md, size_t derived_bits_length) {
	LOG_FUNC();

	if (!derived_bits_length)
		THROW_ERROR("PBKDF2: Derive bits length not specified");

	if (derived_bits_length % 8)
		THROW_ERROR("PBKDF2: Derive bits length not a multiple of 8 bytes");

	if (!iterations)
		THROW_ERROR("PBKDF2: Iterations can't be 0");

	if (!md)
		THROW_ERROR("PBKDF2: Message digest algorithm is empty");

	Handle<std::string> res(new std::string());
	int derived_bytes_length = static_cast<int>(derived_bits_length) >> 3;
	res->resize(static_cast<size_t>(derived_bytes_length));

	if (!PKCS5_PBKDF2_HMAC(
		this->value->c_str(), static_cast<int>(this->value->length()),
		(const byte*)salt->c_str(), static_cast<int>(salt->length()),
		static_cast<int>(iterations), md,
		derived_bytes_length, (byte*)res->c_str())
		) {
		THROW_OPENSSL("PKCS5_PBKDF2_HMAC");
	}

	return res;
}