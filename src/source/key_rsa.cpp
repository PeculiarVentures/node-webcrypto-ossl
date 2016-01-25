#include "key_rsa.h"

JWK_RSA* JWK_RSA_new() {
	return new JWK_RSA;
}
void JWK_RSA_free(JWK_RSA *jwk) {
	delete jwk;
};

ScopedSSL_free(JWK_RSA, JWK_RSA_free);

Handle<ScopedEVP_PKEY> RSA_generate(int modulus, int publicExponent) {
	LOG_FUNC();

	ScopedEVP_PKEY pkey = EVP_PKEY_new();
	RSA *rsa = NULL;
	unsigned long e = RSA_3;
	ScopedBIGNUM bne;


	switch (publicExponent) {
	case 0:
		e = RSA_3;
		break;
	case 1:
		e = RSA_F4;
		break;
	default:
		THROW_ERROR("Unsuported publicExponent value");
	}

	bne = BN_new();
	if (BN_set_word(bne.Get(), e) != 1) {
		THROW_OPENSSL("RSA: E -> BIGNUM");
	}

	rsa = RSA_new();

	if (RSA_generate_key_ex(rsa, modulus, bne.Get(), NULL) != 1) {
		RSA_free(rsa);
		THROW_OPENSSL("RSA_generate_key_ex");
	}

	if (EVP_PKEY_assign_RSA(pkey.Get(), rsa) != 1) {
		RSA_free(rsa);
		THROW_OPENSSL("EVP_PKEY_assign_RSA");
	}

	return Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(pkey));
}

Handle<ScopedJWK_RSA> RSA_export_jwk(EVP_PKEY *pkey, int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	LOG_INFO("Check pkey");
	if (pkey == NULL) {
		THROW_ERROR("Key value is NULL");
	}
	if (pkey->type != EVP_PKEY_RSA) {
		THROW_ERROR("Key is not RSA type");
	}

	LOG_INFO("Create JWK Object");
	JWK_RSA* jwk = JWK_RSA_new();
	Handle<ScopedJWK_RSA> hJwk(new ScopedJWK_RSA(jwk));

	RSA *rsa = pkey->pkey.rsa;

	LOG_INFO("Convert RSA to JWK");
	jwk->type = key_type;
	LOG_INFO("Get RSA public key");
	jwk->n = BN_dup(rsa->n);
	jwk->e = BN_dup(rsa->e);
	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("Get RSA private key");
		jwk->d = BN_dup(rsa->d);
		jwk->p = BN_dup(rsa->p);
		jwk->q = BN_dup(rsa->q);
		jwk->dp = BN_dup(rsa->dmp1);
		jwk->dq = BN_dup(rsa->dmq1);
		jwk->qi = BN_dup(rsa->iqmp);
	}

	return hJwk;
}

Handle<ScopedEVP_PKEY> RSA_import_jwk(Handle<ScopedJWK_RSA> hJwk, int &key_type) {
	LOG_FUNC();

	LOG_INFO("Check key_type");
	if (!(key_type == NODESSL_KT_PRIVATE || key_type == NODESSL_KT_PUBLIC)) {
		THROW_ERROR("Wrong value of key_type");
	}

	if (strcmp(hJwk->Get()->kty, "RSA") != 0) {
		THROW_ERROR("JWK key is not RSA");
	}

	RSA* rsa_key = RSA_new();

	LOG_INFO("set public key");
	rsa_key->n = BN_dup(hJwk->Get()->n.Get());
	rsa_key->e = BN_dup(hJwk->Get()->e.Get());

	if (key_type == NODESSL_KT_PRIVATE) {
		LOG_INFO("set private key");
		rsa_key->d = BN_dup(hJwk->Get()->d.Get());
		rsa_key->p = BN_dup(hJwk->Get()->p.Get());
		rsa_key->q = BN_dup(hJwk->Get()->q.Get());
		rsa_key->dmp1 = BN_dup(hJwk->Get()->dp.Get());
		rsa_key->dmq1 = BN_dup(hJwk->Get()->dq.Get());
		rsa_key->iqmp = BN_dup(hJwk->Get()->qi.Get());
	}

	LOG_INFO("set key");
	ScopedEVP_PKEY pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey.Get(), rsa_key);

	return Handle<ScopedEVP_PKEY>(new ScopedEVP_PKEY(pkey));
}

Handle<ScopedBIO> RSA_sign_buf(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in) {
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

bool RSA_verify_buf(Handle<ScopedEVP_PKEY> key, const EVP_MD *md, Handle<ScopedBIO> in, Handle<ScopedBIO> signature) {
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

Handle<ScopedBIO> RSA_OAEP_encrypt(
	Handle<ScopedEVP_PKEY> hKey,
	const EVP_MD *md,
	Handle<ScopedBIO> hData,
	Handle<ScopedBIO> hLabel
	)
{
	LOG_FUNC();

	EVP_PKEY* pKey = hKey->Get();

	ScopedEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(pKey, NULL));
	if (ctx.isEmpty()) {
		THROW_OPENSSL("EVP_PKEY_CTX_new");
	}

	// EVP_EncryptInit | EVP_DecryptInit

	if (EVP_PKEY_CTX_set_rsa_padding(ctx.Get(), RSA_PKCS1_OAEP_PADDING) < 1) {
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_padding");
	}
	if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.Get(), md) < 1) {
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_oaep_md");
	}
	if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.Get(), md) < 1) {
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_mgf1_md");
	}
		
	if (!hLabel->isEmpty()) {
		LOG_INFO("Set label for RSA OAEP");
		char *label;
		int label_len = BIO_get_mem_data(hLabel->Get(), &label);
		char *label_copy;
		memcpy(label_copy, label, label_len);
		if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.Get(), label_copy,	label_len)<1) {
			THROW_OPENSSL("EVP_PKEY_CTX_set0_rsa_oaep_label");
		}
	}

	// EVP_PKEY_encrypt | EVP_PKEY_decrypt
	// Determine the maximum length of the output.
	
	// Do the actual encryption/decryption.
	

	//Put result to ScopdBIO	
}

static std::string RSA_OAEP_decrypt(
	EVP_PKEY *pkey,
	char *digestName,
	const byte *data,
	size_t datalen,
	char *label,
	int labellen)
{
	LOG_FUNC();

	EVP_PKEY_CTX *rctx = EVP_PKEY_CTX_new(pkey, NULL);

	const EVP_MD *md = EVP_get_digestbyname(digestName);
	if (!md) {
		THROW_OPENSSL("EVP_get_digestbyname");
	}

	if (EVP_PKEY_decrypt_init(rctx) < 0) {
		THROW_OPENSSL("EVP_PKEY_decrypt_init");
	}

	if (EVP_PKEY_CTX_set_rsa_padding(rctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
		EVP_PKEY_CTX_free(rctx);
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_padding");
	}

	if (label && labellen) {
		LOG_INFO("RsaOAEP::Set label parameter");
		unsigned char *buf = NULL;
		int num = BN_num_bytes(pkey->pkey.rsa->n);
		buf = static_cast<unsigned char*>(OPENSSL_malloc(num));
		if (RSA_padding_add_PKCS1_OAEP(buf, num, data, datalen, (const unsigned char*)(label), labellen) < 1) {
			OPENSSL_free(buf);
			EVP_PKEY_CTX_free(rctx);
			THROW_OPENSSL("RSA_padding_add_PKCS1_OAEP");
		}
	}

	if (EVP_PKEY_CTX_set_rsa_oaep_md(rctx, md) <= 0) {
		EVP_PKEY_CTX_free(rctx);
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_oaep_md");
	}

	size_t declen;
	if (EVP_PKEY_decrypt(rctx, NULL, &declen, data, datalen) <= 0) {
		EVP_PKEY_CTX_free(rctx);
		THROW_OPENSSL("EVP_PKEY_decrypt");
	}

	byte *dec = (byte*)OPENSSL_malloc(declen);

	if (EVP_PKEY_decrypt(rctx, dec, &declen, data, datalen) <= 0) {
		OPENSSL_free(dec);
		EVP_PKEY_CTX_free(rctx);
		THROW_OPENSSL("EVP_PKEY_decrypt");
	}

	std::string res((char *)dec, declen);

	EVP_PKEY_CTX_free(rctx);

	return res;
}