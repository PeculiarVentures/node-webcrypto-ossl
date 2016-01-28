#include "ec_dsa.h"

Handle<ScopedBIO> EC_DSA_sign(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in) {
	LOG_FUNC();

	ScopedEC_KEY ec = EVP_PKEY_get1_EC_KEY(key->Get());
	if (ec.isEmpty()) {
		THROW_OPENSSL("EVP_PKEY_get1_EC_KEY");
	}

	unsigned char sig[2048] = { 0 };
	unsigned int siglen = 0;

	unsigned char* buf = NULL;
	unsigned int buflen = BIO_get_mem_data(in->Get(), &buf);

	if (ECDSA_sign(md->type, buf, buflen, sig, &siglen, ec.Get()) < 1) {
		THROW_OPENSSL(RSA_sign);
	}

	LOG_INFO("write to BIO");
	char *bio = (char*)OPENSSL_malloc(siglen);
	BIO *out = BIO_new_mem_buf(sig, siglen);
	BIO_set_flags(out, BIO_CLOSE);

	return Handle<ScopedBIO>(new ScopedBIO(out));
}

bool EC_DSA_verify(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in, Handle<ScopedBIO> signature) {
	LOG_FUNC();

	ScopedEC_KEY ec = EVP_PKEY_get1_EC_KEY(key->Get());
	if (ec.isEmpty()) {
		THROW_OPENSSL("EVP_PKEY_get1_EC_KEY");
	}

	LOG_INFO("prepare data");
	unsigned char* data = NULL;
	unsigned int datalen = BIO_get_mem_data(in->Get(), &data);

	LOG_INFO("prepare signature");
	unsigned char* sig = NULL;
	unsigned int siglen = BIO_get_mem_data(signature->Get(), &sig);

	int res = ECDSA_verify(md->type, data, datalen, sig, siglen, ec.Get());
	if (res == -1) {
		THROW_OPENSSL("ECDSA_verify");
	}

	return res == 1;
}