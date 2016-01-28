#include "ec_dh.h"

Handle<ScopedBIO> ECDH_derive_key(Handle<ScopedEVP_PKEY> pkey, Handle<ScopedEVP_PKEY> pubkey, size_t &secret_len) {
	LOG_FUNC();

	ScopedEVP_PKEY_CTX ctx;
	unsigned char *secret;
	std::string res;

	LOG_INFO("Create the context for the shared secret derivation");
	ctx = EVP_PKEY_CTX_new(pkey->Get(), NULL);
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
	if (1 != EVP_PKEY_derive(ctx.Get(), NULL, &secret_len)) {
		THROW_OPENSSL("EVP_PKEY_derive");
	}

	LOG_INFO("Create the buffer");
	if (NULL == (secret = static_cast<unsigned char*>(OPENSSL_malloc(secret_len)))) {
		THROW_OPENSSL("EVP_PKEY_derive_init");
	}

	LOG_INFO("Derive the shared secret");
	if (1 != (EVP_PKEY_derive(ctx.Get(), secret, &secret_len))) {
		OPENSSL_free(secret);
		THROW_OPENSSL("EVP_PKEY_derive_init");
	}

	Handle<ScopedBIO> dkey(new ScopedBIO(BIO_new_mem_buf(secret, secret_len)));
	OPENSSL_free(secret);

	BIO_set_flags(dkey->Get(), BIO_CLOSE);

	return dkey;
}