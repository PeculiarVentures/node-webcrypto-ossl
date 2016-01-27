#include "rsa_pkcs1.h"

Handle<ScopedBIO> RSA_PKCS1_sign(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in) {
	LOG_FUNC();

	ScopedRSA rsa = EVP_PKEY_get1_RSA(key->Get());
	if (rsa.isEmpty()) {
		THROW_OPENSSL("EVP_PKEY_get1_RSA");
	}

	unsigned char sig[2048] = { 0 };
	unsigned int siglen = 0;

	unsigned char* buf = NULL;
	unsigned int buflen = BIO_get_mem_data(in->Get(), &buf);

	if (RSA_sign(md->type, buf, buflen, sig, &siglen, rsa.Get()) < 1) {
		THROW_OPENSSL(RSA_sign);
	}

	char *bio = (char*)OPENSSL_malloc(siglen);
	BIO *out = BIO_new_mem_buf(sig, siglen);
	BIO_set_flags(out, BIO_CLOSE);

	return Handle<ScopedBIO>(new ScopedBIO(out));
}

bool RSA_PKCS1_verify(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in, Handle<ScopedBIO> signature) {
	LOG_FUNC();

	ScopedRSA rsa = EVP_PKEY_get1_RSA(key->Get());
	if (rsa.isEmpty()) {
		THROW_OPENSSL("EVP_PKEY_get1_RSA");
	}

	LOG_INFO("prepare data");
	unsigned char* data = NULL;
	unsigned int datalen = BIO_get_mem_data(in->Get(), &data);

	LOG_INFO("prepare signature");
	unsigned char* sig = NULL;
	unsigned int siglen = BIO_get_mem_data(signature->Get(), &sig);

	int res = RSA_verify(md->type, data, datalen, sig, siglen, rsa.Get());
	if (res == -1) {
		THROW_OPENSSL("RSA_verify");
	}

	return res == 1;
}