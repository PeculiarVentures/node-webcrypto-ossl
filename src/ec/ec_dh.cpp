#include "ec_dh.h"

Handle<std::string> ECDH_derive_key(Handle<ScopedEVP_PKEY> pkey, Handle<ScopedEVP_PKEY> pubkey, size_t &secret_len) {
	LOG_FUNC();

	size_t aes_key_length = secret_len;

	ScopedEVP_PKEY_CTX ctx;
	Handle<std::string>hSecret(new std::string());

	LOG_INFO("Create the context for the shared secret derivation");
	ctx = EVP_PKEY_CTX_new(pkey->Get(), nullptr);
	if (ctx.isEmpty())
		THROW_OPENSSL("EVP_PKEY_CTX_new");

	LOG_INFO("Initialise");
	if (1 != EVP_PKEY_derive_init(ctx.Get())) {
		THROW_OPENSSL("EVP_PKEY_derive_init");
	}

	LOG_INFO("Provide the peer public key");
	if (1 != EVP_PKEY_derive_set_peer(ctx.Get(), pubkey->Get())) {
		THROW_OPENSSL("EVP_PKEY_derive_set_peer");
	}

	LOG_INFO("Determine buffer length for shared secret");
	if (1 != EVP_PKEY_derive(ctx.Get(), nullptr, &secret_len)) {
		THROW_OPENSSL("EVP_PKEY_derive");
	}

	LOG_INFO("Create the buffer");
	hSecret->resize(secret_len);
	unsigned char *secret = (unsigned char *)hSecret->c_str();

	LOG_INFO("Derive the shared secret");
	if (1 != (EVP_PKEY_derive(ctx.Get(), secret, &secret_len))) {
		THROW_OPENSSL("EVP_PKEY_derive_init");
	}
	hSecret->resize(aes_key_length);

	return hSecret;
}

template <typename T>
T NumBitsToBytes(T x) {
	return (x / 8) + (7 + (x % 8)) / 8;
}

void TruncateToBitLength(size_t length_bits, std::string* bytes) {
	size_t length_bytes = NumBitsToBytes(length_bits);

	if (bytes->size() != length_bytes) {
		if (length_bytes < bytes->size())
			bytes->resize(length_bytes);
		else
			THROW_ERROR("Wrong leng for truncate");
	}

	size_t remainder_bits = length_bits % 8;

	// Zero any "unused bits" in the final byte.
	if (remainder_bits)
		(*bytes)[bytes->size() - 1] &= ~((0xFF) >> remainder_bits);
}

int EC_get_named_curve(EC_KEY *ec_key) {
	LOG_FUNC();

	const EC_GROUP  *group;
	int nid;
	if (ec_key == NULL || (group = EC_KEY_get0_group(ec_key)) == NULL)
	{
		THROW_OPENSSL("EC_KEY_get0_group");
	}

	nid = EC_GROUP_get_curve_name(group);
	return nid;
}

Handle<std::string> ECDH_derive_bits(
	Handle<ScopedEVP_PKEY> pubkey,
	Handle<ScopedEVP_PKEY> pkey,
	bool has_optional_length_bits,
	unsigned int optional_length_bits)
{
	LOG_FUNC();

	// pkey must be PRIVATE EC
	ScopedEC_KEY ecPrivate(EVP_PKEY_get1_EC_KEY(pkey->Get()));
	if (ecPrivate.isEmpty() || !EC_KEY_get0_private_key(ecPrivate.Get()))
		THROW_ERROR("EVP_PKEY_get1_EC_KEY. Can not get EC private key");
	// pubkey must be PUBLIC EC
	ScopedEC_KEY ecPublic(EVP_PKEY_get1_EC_KEY(pubkey->Get()));
	if (ecPublic.isEmpty())
		THROW_OPENSSL("EVP_PKEY_get1_EC_KEY. Can not get EC public key");

	// curves of corves must match.
	if (EC_get_named_curve(ecPrivate.Get()) != EC_get_named_curve(ecPublic.Get())) {
		THROW_ERROR("Named corves of EC keys are not equals");
	}
	const EC_POINT* public_key_point = EC_KEY_get0_public_key(ecPublic.Get());
	// The size of the shared secret is the field size in bytes (rounded up).
	// Note that, if rounding was required, the most significant bits of the
	// secret are zero. So for P-521, the maximum length is 528 bits, not 521.
	int field_size_bytes = NumBitsToBytes(
		EC_GROUP_get_degree(EC_KEY_get0_group(ecPrivate.Get())));
	// If a desired key length was not specified, default to the field size
	// (rounded up to nearest byte).
	unsigned int length_bits =
		has_optional_length_bits ? optional_length_bits : field_size_bytes * 8;

	Handle<std::string> derived_bytes(new std::string());

	// Short-circuit when deriving an empty key.
	if (length_bits == 0) {
		// derived_bytes->clear();
		return derived_bytes;
	}
	if (length_bits > static_cast<unsigned int>(field_size_bytes * 8))
		THROW_ERROR("ECDH length too big");
	// Resize to target length in bytes (BoringSSL can operate on a shorter
	// buffer than field_size_bytes).
	derived_bytes->resize(NumBitsToBytes(length_bits));
	int result =
		ECDH_compute_key((void *)derived_bytes->c_str(), derived_bytes->size(),
			public_key_point, ecPrivate.Get(), 0);
	if (result < 0 || static_cast<size_t>(result) != derived_bytes->size())
		THROW_OPENSSL("ECDH_compute_key");
	TruncateToBitLength(length_bits, derived_bytes.get());
	return derived_bytes;
}