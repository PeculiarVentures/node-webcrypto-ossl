#include "ec_dh.h"

Handle<std::string> ECDH_derive_key(Handle<ScopedEVP_PKEY> pkey, Handle<ScopedEVP_PKEY> pubkey, size_t &secret_len) {
	LOG_FUNC();

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

	return hSecret;
}