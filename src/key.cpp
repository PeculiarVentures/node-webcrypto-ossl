#include <stdexcept>
#include <nan.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#define DATA_FORMAT_DER 0
#define DATA_FORMAT_PEM 1

#ifndef byte
typedef unsigned char byte;
#endif

// #define V8_DEBUG

class FunctionLog {
public:
	FunctionLog(const char *name) {
		name_ = std::string(name);
#ifdef V8_DEBUG
		std::string res = "begin " + name_;
		puts(res.c_str());
#endif 
	}

	~FunctionLog() {
#ifdef V8_DEBUG
		std::string res = "end   " + name_;
		puts(res.c_str());
#endif 
	}
protected:
	std::string name_;
};

void MessageLog(char* type, char* name) {
	fprintf(stdout, "%s: %s\n", type, name);
}

#ifdef V8_DEBUG
#define LOG_INFO(name) MessageLog("info ", name)
#else
#define LOG_INFO(name)
#endif

#define LOG_FUNC() \
	FunctionLog __v8_func(__FUNCTION__);

X509_SIG *PKCS8_set0_pbe(
	const char *pass,
	int passlen,
	PKCS8_PRIV_KEY_INFO *p8inf,
	X509_ALGOR *pbe)
{
	LOG_FUNC();

	X509_SIG *p8;
	ASN1_OCTET_STRING *enckey;

	enckey =
		PKCS12_item_i2d_encrypt(pbe, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO),
			pass, passlen, p8inf, 1);
	if (!enckey) {
		PKCS12err(132, PKCS12_R_ENCRYPT_ERROR);
		return NULL;
	}

	if ((p8 = X509_SIG_new()) == NULL) {
		PKCS12err(132, ERR_R_MALLOC_FAILURE);
		ASN1_OCTET_STRING_free(enckey);
		return NULL;
	}
	X509_ALGOR_free(p8->algor);
	ASN1_OCTET_STRING_free(p8->digest);
	p8->algor = pbe;
	p8->digest = enckey;

	return p8;
}

static std::string OPENSSL_get_errors() {
	LOG_FUNC();

	BIO* bio = BIO_new(BIO_s_mem());
	char *str;
	ERR_print_errors(bio);

	int strlen = BIO_get_mem_data(bio, &str);
	std::string res(str, strlen);

	BIO_free(bio);
	return res;
}

#define THROW_OPENSSL(text) {LOG_INFO(text);throw std::runtime_error(OPENSSL_get_errors().c_str());}

#define V8_CATCH_OPENSSL()\
	catch (std::exception& e) {Nan::ThrowError(e.what());return;}

static v8::Local<v8::Object> bn2bin(BIGNUM* bn) {
	LOG_FUNC();
	int n = BN_num_bytes(bn);

	v8::Local<v8::Object> v8Buf = Nan::NewBuffer(n).ToLocalChecked();
	unsigned char* buf = (unsigned char*)node::Buffer::Data(v8Buf);
	if (!BN_bn2bin(bn, buf)) {
		THROW_OPENSSL("BN_bn2bin");
	}

	return v8Buf;
}

static v8::Local<v8::Object>s2b(std::string& buf) {
	LOG_FUNC();

	v8::Local<v8::Object> v8Buf = Nan::NewBuffer(buf.length()).ToLocalChecked();
	char *data = node::Buffer::Data(v8Buf);
	memcpy(data, buf.c_str(), buf.length());

	return v8Buf;
}

#define V8_RETURN_BUFFER(strbuf) info.GetReturnValue().Set(s2b(strbuf));

static void sign(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey, char* digestName)
{
	LOG_FUNC();

	/* Returned to caller */
	int result = -1;

	if (*sig)
		OPENSSL_free(*sig);

	*sig = NULL;
	*slen = 0;

	EVP_MD_CTX* ctx = NULL;
	char *err = NULL;
	BIO *bmd = BIO_new(BIO_f_md());

	do
	{
		BIO_get_md_ctx(bmd, &ctx);
		if (ctx == NULL) {
			err = "EVP_MD_CTX_create failed";
			break;
		}

		const EVP_MD* md = EVP_get_digestbyname(digestName);
		if (md == NULL) {
			err = "EVP_get_digestbyname failed";
			break;
		}

		int rc = EVP_DigestInit_ex(ctx, md, NULL);
		if (rc != 1) {
			err = "EVP_DigestInit_ex failed";
			break;
		}

		rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
		if (rc != 1) {
			err = "EVP_DigestSignInit failed";
			break;
		}

		rc = EVP_DigestSignUpdate(ctx, msg, mlen);
		if (rc != 1) {
			err = "EVP_DigestSignUpdate failed";
			break; /* failed */
		}

		size_t req = 0;
		rc = EVP_DigestSignFinal(ctx, NULL, &req);
		if (rc != 1) {
			err = "EVP_DigestSignFinal failed";
			break; /* failed */
		}

		if (!(req > 0)) {
			err = "EVP_DigestSignFinal empty signature value";
			break; /* failed */
		}

		*sig = (byte *)OPENSSL_malloc(req);
		if (*sig == NULL) {
			err = "OPENSSL_malloc failed";
			break; /* failed */
		}

		*slen = req;
		rc = EVP_DigestSignFinal(ctx, *sig, slen);
		if (rc != 1) {
			err = "EVP_DigestSignFinal failed";
			break; /* failed */
		}

		result = 0;

	} while (0);

	BIO_free(bmd);

	if (err) {
		THROW_OPENSSL(err);
	}
}

int verify(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey, char* digestName)
{
	LOG_FUNC();

	/* Returned to caller */
	int result = -1;

	EVP_MD_CTX* ctx = NULL;
	char* err = NULL;
	BIO *bmd = BIO_new(BIO_f_md());

	do
	{
		BIO_get_md_ctx(bmd, &ctx);
		if (ctx == NULL) {
			err = "EVP_MD_CTX_create failed";
			break;
		}

		const EVP_MD* md = EVP_get_digestbyname(digestName);
		if (md == NULL) {
			err = "EVP_get_digestbyname failed";
			break; /* failed */
		}

		int rc = EVP_DigestInit_ex(ctx, md, NULL);
		if (rc != 1) {
			err = "EVP_DigestInit_ex failed";
			break; /* failed */
		}

		rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
		if (rc != 1) {
			err = "EVP_DigestVerifyInit failed";
			break; /* failed */
		}

		rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
		if (rc != 1) {
			err = "EVP_DigestVerifyUpdate failed";
			break; /* failed */
		}

		rc = EVP_DigestVerifyFinal(ctx, sig, slen);
		if (rc == -1) {
			err = "EVP_DigestVerifyFinal failed";
			break; /* failed */
		}
		result = rc;

		break;

	} while (0);

	BIO_free(bmd);

	if (err) {
		THROW_OPENSSL(err);
	}

	return result;
}

std::string deriveKey(EVP_PKEY *pkey, EVP_PKEY* pubkey, size_t &secret_len)
{
	LOG_FUNC();

	EVP_PKEY_CTX *ctx;
	unsigned char *secret;
	std::string res;

	LOG_INFO("Create the context for the shared secret derivation");
	if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))
		THROW_OPENSSL("EVP_PKEY_CTX_new");

	LOG_INFO("Initialise");
	if (1 != EVP_PKEY_derive_init(ctx)) {
		EVP_PKEY_CTX_free(ctx);
		THROW_OPENSSL("EVP_PKEY_derive_init");
	}

	LOG_INFO("Provide the peer public key");
	if (1 != EVP_PKEY_derive_set_peer(ctx, pubkey)) {
		EVP_PKEY_CTX_free(ctx);
		THROW_OPENSSL("EVP_PKEY_derive_set_peer");
	}

	LOG_INFO("Determine buffer length for shared secret");
	if (1 != EVP_PKEY_derive(ctx, NULL, &secret_len)) {
		EVP_PKEY_CTX_free(ctx);
		THROW_OPENSSL("EVP_PKEY_derive");
	}

	LOG_INFO("Create the buffer");
	if (NULL == (secret = static_cast<unsigned char*>(OPENSSL_malloc(secret_len)))) {
		EVP_PKEY_CTX_free(ctx);
		THROW_OPENSSL("EVP_PKEY_derive_init");
	}

	LOG_INFO("Derive the shared secret");
	if (1 != (EVP_PKEY_derive(ctx, secret, &secret_len))) {
		OPENSSL_free(secret);
		EVP_PKEY_CTX_free(ctx);
		THROW_OPENSSL("EVP_PKEY_derive_init");
	}

	res = std::string((char *)secret, (int)secret_len);

	LOG_INFO("Free data");
	EVP_PKEY_CTX_free(ctx);
	OPENSSL_free(secret);

	/* Never use a derived secret directly. Typically it is passed
	* through some hash function to produce a key */
	return res;
}

static std::string RSA_OAEP_encrypt(
	EVP_PKEY *pkey,
	char *digestName,
	const byte *data,
	size_t datalen,
	char *label,
	int labellen
	)
{
	LOG_FUNC();

	if (!pkey) {
		throw std::runtime_error("pkey is NULL");
	}

	EVP_PKEY_CTX *rctx = EVP_PKEY_CTX_new(pkey, NULL);

	const EVP_MD *md = EVP_get_digestbyname(digestName);
	if (!md) {
		THROW_OPENSSL("EVP_get_digestbyname");
	}

	if (EVP_PKEY_encrypt_init(rctx) < 0) {
		THROW_OPENSSL("EVP_PKEY_encrypt_init");
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
			THROW_OPENSSL(RSA_padding_add_PKCS1_OAEP);
		}
	}

	if (EVP_PKEY_CTX_set_rsa_oaep_md(rctx, md) <= 0) {
		EVP_PKEY_CTX_free(rctx);
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_oaep_md");
	}

	size_t enclen;
	if (EVP_PKEY_encrypt(rctx, NULL, &enclen, data, datalen) <= 0) {
		EVP_PKEY_CTX_free(rctx);
		THROW_OPENSSL("EVP_PKEY_encrypt");
	}

	byte *enc = static_cast<byte*>(OPENSSL_malloc(enclen));

	if (EVP_PKEY_encrypt(rctx, enc, &enclen, data, datalen) <= 0) {
		OPENSSL_free(enc);
		EVP_PKEY_CTX_free(rctx);
		THROW_OPENSSL("EVP_PKEY_encrypt");
	}

	std::string res((char *)enc, enclen);

	EVP_PKEY_CTX_free(rctx);

	return res;
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
			THROW_OPENSSL(RSA_padding_add_PKCS1_OAEP);
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

static std::string k2pkcs8(
	EVP_PKEY* pkey,
	int dataFormat,
	const EVP_CIPHER *cipher,
	char *pbe_alg,
	char *pass,
	size_t passlen,
	byte *salt,
	size_t saltlen,
	int iter
	)
{
	LOG_FUNC();

	std::string res;
	PKCS8_PRIV_KEY_INFO *p8info = NULL;
	BIO *out;
	char *buf;
	int pbe_nid = -1;

	p8info = EVP_PKEY2PKCS8(pkey);
	if (!p8info) {
		THROW_OPENSSL("EVP_PKEY2PKCS8");
	}

	if (cipher) {
		PKCS8_PRIV_KEY_INFO_free(p8info);
		throw std::runtime_error("Method is not implemented");
	}
	else {
		//no encrypt
		out = BIO_new(BIO_s_mem());

		switch (dataFormat)
		{
		case DATA_FORMAT_PEM:
			if (PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info) <= 0) {
				PKCS8_PRIV_KEY_INFO_free(p8info);
				BIO_free(out);
				THROW_OPENSSL("PEM_write_bio_PKCS8_PRIV_KEY_INFO");
			}
			break;
		default:
			if (i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info) <= 0) {
				PKCS8_PRIV_KEY_INFO_free(p8info);
				BIO_free(out);
				THROW_OPENSSL("i2d_PKCS8PrivateKeyInfo_bio");
			}
			break;
		}
	}

	int buflen = BIO_get_mem_data(out, &buf);
	res = std::string(buf, buflen);

	PKCS8_PRIV_KEY_INFO_free(p8info);
	BIO_free(out);

	return res;
}

static std::string k2spki(EVP_PKEY* pkey, int dataFormat) {
	LOG_FUNC();

	char *buf;
	int buflen;
	std::string res;
	BIO *out = BIO_new(BIO_s_mem());

	switch (dataFormat) {
	case DATA_FORMAT_PEM:
		if (PEM_write_bio_PUBKEY(out, pkey) <= 0) {
			BIO_free(out);
			THROW_OPENSSL("i2d_PUBKEY_bio");
		}
		break;
	default:
		if (i2d_PUBKEY_bio(out, pkey) <= 0) {
			BIO_free(out);
			THROW_OPENSSL("i2d_PUBKEY_bio");
		}
	}

	buflen = BIO_get_mem_data(out, &buf);
	res = std::string(buf, buflen);

	BIO_free(out);

	return res;
}

EVP_PKEY* pkcs82k(char *buf, int buflen, int dataFormat) {
	LOG_FUNC();

	BIO *in = BIO_new(BIO_s_mem());
	EVP_PKEY* pubkey = NULL;

	char *d = static_cast<char *>(OPENSSL_malloc(buflen));
	memcpy(d, buf, buflen);
	BIO_write(in, d, buflen);

	BIO_seek(in, 0);

	switch (dataFormat) {
	case DATA_FORMAT_PEM:
		pubkey = PEM_read_bio_PrivateKey(in, NULL, 0, NULL);
		if (pubkey == NULL) {
			BIO_free(in);
			THROW_OPENSSL("PEM_read_bio_PrivateKey");
		}
		break;
	default:
		pubkey = d2i_PrivateKey_bio(in, NULL);
		if (pubkey == NULL) {
			BIO_free(in);
			THROW_OPENSSL("d2i_PrivateKey_bio");
		}
	}

	BIO_free(in);

	return pubkey;
}

EVP_PKEY* spki2k(char *buf, int buflen, int dataFormat) {
	LOG_FUNC();

	BIO *in = BIO_new(BIO_s_mem());
	BIO_write(in, buf, buflen);
	EVP_PKEY* pubkey = NULL;

	BIO_seek(in, 0);

	switch (dataFormat) {
	case DATA_FORMAT_PEM:
		pubkey = PEM_read_bio_PUBKEY(in, NULL, 0, NULL);
		if (pubkey == NULL) {
			BIO_free(in);
			THROW_OPENSSL("PEM_read_bio_PUBKEY");
		}
		break;
	default:
		pubkey = d2i_PUBKEY_bio(in, NULL);
		if (pubkey == NULL) {
			BIO_free(in);
			THROW_OPENSSL("d2i_PUBKEY_bio");
		}
	}

	BIO_free(in);

	return pubkey;
}

class Key {
public:
	Key() {
		LOG_FUNC();

		this->_internal = EVP_PKEY_new();
	}
	Key(EVP_PKEY *key) {
		LOG_FUNC();

		this->_internal = key;
	}
	~Key() {
		LOG_FUNC();

		this->dispose();
		this->_internal = NULL;
	}

	//Returns in PKCS8
	std::string writePrivateKey() {
		LOG_FUNC();

		BIO *out;
		char *buf;
		out = BIO_new(BIO_s_mem());
		if (i2d_PKCS8PrivateKeyInfo_bio(out, this->internal()) <= 0) {
			BIO_free(out);
			throw std::runtime_error("i2d_PKCS8PrivateKeyInfo_bio");
		}

		int buflen = BIO_get_mem_data(out, &buf);
		std::string res(buf, buflen);

		BIO_free(out);

		return res;
	}

	int type() {
		LOG_FUNC();

		return this->internal()->type;
	}

	int size() {
		LOG_FUNC();

		return EVP_PKEY_size(this->internal());
	}

	void dispose() {
		LOG_FUNC();

		if (this->_internal) {
			EVP_PKEY_free(this->_internal);
			this->_internal = NULL;
		}
	}



	int generateRsa(int modulus, int publicExponent) {
		LOG_FUNC();

		EVP_PKEY *pkey = EVP_PKEY_new();
		RSA *rsa = NULL;
		unsigned long e = RSA_3;
		BIGNUM *bne = NULL;


		switch (publicExponent) {
		case 0:
			e = RSA_3;
			break;
		case 1:
			e = RSA_F4;
			break;
		default:
			goto err;
		}

		bne = BN_new();
		if (BN_set_word(bne, e) != 1) {
			goto err;
		}

		rsa = RSA_new();

		if (RSA_generate_key_ex(rsa, modulus, bne, NULL) != 1) {
			goto err;
		}
		BN_free(bne);
		if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
			goto err;
		}

		this->dispose();
		this->_internal = pkey;

		return 1;
	err:
		ERR_print_errors_fp(stdout);
		if (rsa) RSA_free(rsa);
		if (pkey) EVP_PKEY_free(pkey);
		if (bne) BN_free(bne);
		return 0;
	}

	int generateEc(int nidEc) {
		LOG_FUNC();

		EVP_PKEY *pkey = NULL;

		EC_KEY *eckey = EC_KEY_new_by_curve_name(nidEc);

		if (!eckey) {
			THROW_OPENSSL("EC_KEY_new_by_curve_name");
		}
		if (!EC_KEY_generate_key(eckey)) {
			EC_KEY_free(eckey);
			THROW_OPENSSL("EC_KEY_generate_key");
		}

		pkey = EVP_PKEY_new();

		if (EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
			EVP_PKEY_free(pkey);
			THROW_OPENSSL("EVP_PKEY_assign_EC_KEY");
		}

		this->dispose();
		this->_internal = pkey;

		return 1;
	}

	EVP_PKEY* internal() {
		LOG_FUNC();

		return this->_internal;
	}

	void internal(EVP_PKEY *pkey) {
		LOG_FUNC();

		this->dispose();
		this->_internal = pkey;
	}

protected:
	EVP_PKEY *_internal = NULL;

};

class WKey : public Nan::ObjectWrap {
public:
	static void Init(v8::Handle<v8::Object> exports) {
		v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
		tpl->SetClassName(Nan::New("Key").ToLocalChecked());
		tpl->InstanceTemplate()->SetInternalFieldCount(1);

		//generate
		SetPrototypeMethod(tpl, "generateRsa", GenerateRsa);
		SetPrototypeMethod(tpl, "generateEc", GenerateEc);

		//write
		SetPrototypeMethod(tpl, "writePKCS8", WritePKCS8);
		SetPrototypeMethod(tpl, "writeSPKI", WriteSPKI);

		//JWK
		SetPrototypeMethod(tpl, "exportJWK", ExportJWK);
		SetPrototypeMethod(tpl, "importJWK", ImportJWK);

		//read
		SetPrototypeMethod(tpl, "readPKCS8", ReadPKCS8);
		SetPrototypeMethod(tpl, "readSPKI", ReadSPKI);

		//OAEP
		SetPrototypeMethod(tpl, "encryptRsaOAEP", EncryptRsaOAEP);
		SetPrototypeMethod(tpl, "decryptRsaOAEP", DecryptRsaOAEP);

		v8::Local<v8::ObjectTemplate> itpl = tpl->InstanceTemplate();
		Nan::SetAccessor(itpl, Nan::New("type").ToLocalChecked(), Type);

		constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());

		exports->Set(Nan::New("Key").ToLocalChecked(), tpl->GetFunction());
	}

	static
		v8::Local<v8::Object> NewInstance(int argc, v8::Local<v8::Value> argv[]) {
		v8::Local<v8::Function> cons = Nan::New(constructor());
		return Nan::NewInstance(cons, argc, argv).ToLocalChecked();
	}

	Key data;
private:

	explicit WKey() : data(Key()) {
		LOG_FUNC();
	}
	~WKey() {
		LOG_FUNC();
	}

	static NAN_METHOD(New) {
		LOG_FUNC();

		if (info.IsConstructCall()) {

			WKey * obj = new WKey();
			obj->Wrap(info.This());
			info.GetReturnValue().Set(info.This());

		}
		else {
			const int argc = 1;
			v8::Local<v8::Value> argv[argc] = { info[0] };
			v8::Local<v8::Function> cons = Nan::New(constructor());
			info.GetReturnValue().Set(
				Nan::NewInstance(cons, argc, argv).ToLocalChecked());
		}
	}

	/*
	format: String
	pass: String
	salt: String
	iter: Number
	*/
	static NAN_METHOD(WritePKCS8) {
		LOG_FUNC();

		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		std::string res;
		int format = DATA_FORMAT_DER;
		v8::String::Utf8Value formatStr(info[0]->ToString());
		if (strcmp(*formatStr, "pem") == 0)
			format = DATA_FORMAT_PEM;

		try {
			if (info[1]->IsUndefined()) {
				//no crypto
				res = k2pkcs8(obj->data.internal(), format, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
			}
			else {
				//crypto
				v8::String::Utf8Value pass(info[1]->ToString());
				int passlen = info[1]->ToString()->Length();
				byte *salt = (byte *)node::Buffer::Data(info[2]->ToObject());
				int saltlen = node::Buffer::Length(info[2]->ToObject());
				int iter = info[3]->ToNumber()->Int32Value();

				res = k2pkcs8(obj->data.internal(), format, EVP_aes_256_gcm(), "", *pass, passlen, salt, saltlen, iter);
			}
		}
		V8_CATCH_OPENSSL();

		V8_RETURN_BUFFER(res);
	}

	/*
	format: String
	*/
	static NAN_METHOD(WriteSPKI) {
		LOG_FUNC();

		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		std::string res;
		int format = DATA_FORMAT_DER;
		v8::String::Utf8Value formatStr(info[0]->ToString());
		if (strcmp(*formatStr, "pem") == 0)
			format = DATA_FORMAT_PEM;
		try {
			res = k2spki(obj->data.internal(), format);
		}
		V8_CATCH_OPENSSL();

		V8_RETURN_BUFFER(res);
	}

	/*
	buffer: Buffer
	format: String
	*/
	static NAN_METHOD(ReadSPKI) {
		LOG_FUNC();

		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		EVP_PKEY* pkey;
		//buffer
		char *buf = node::Buffer::Data(info[0]->ToObject());
		int buflen = node::Buffer::Length(info[0]->ToObject());

		//format
		int format = DATA_FORMAT_DER;
		v8::String::Utf8Value formatStr(info[1]->ToString());

		if (strcmp(*formatStr, "pem") == 0)
			format = DATA_FORMAT_PEM;
		try {
			pkey = spki2k(buf, buflen, format);
		}
		V8_CATCH_OPENSSL();

		obj->data.internal(pkey);

		info.GetReturnValue().SetUndefined();
	}

	/*
	buffer: Buffer
	format: String
	*/
	static NAN_METHOD(ReadPKCS8) {
		LOG_FUNC();
		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		EVP_PKEY* pkey;
		//buffer
		char *buf = node::Buffer::Data(info[0]->ToObject());
		int buflen = node::Buffer::Length(info[0]->ToObject());

		//format
		int format = DATA_FORMAT_DER;
		v8::String::Utf8Value formatStr(info[1]->ToString());

		if (strcmp(*formatStr, "pem") == 0)
			format = DATA_FORMAT_PEM;
		try {
			pkey = pkcs82k(buf, buflen, format);
		}
		V8_CATCH_OPENSSL();

		obj->data.internal(pkey);

		info.GetReturnValue().SetUndefined();
	}

	/*
	data: Buffer
	hash: String
	label: Buffer
	*/
	static NAN_METHOD(EncryptRsaOAEP) {
		LOG_FUNC();
		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		//data
		char *data = node::Buffer::Data(info[0]->ToObject());
		size_t datalen = node::Buffer::Length(info[0]->ToObject());
		//hash
		v8::String::Utf8Value hash(info[1]->ToString());

		//label
		char *label = NULL;
		size_t labellen = 0;
		if (!info[2]->IsUndefined()) {
			label = node::Buffer::Data(info[2]->ToObject());
			labellen = node::Buffer::Length(info[2]->ToObject());
		}

		std::string enc;
		try {
			enc = RSA_OAEP_encrypt(obj->data.internal(), *hash, (const byte*)data, datalen, label, labellen);
		}
		V8_CATCH_OPENSSL();

		V8_RETURN_BUFFER(enc);
	}

	/*
	data: Buffer
	hash: String
	label: Buffer
	*/
	static NAN_METHOD(DecryptRsaOAEP) {
		LOG_FUNC();

		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		//data
		char *data = node::Buffer::Data(info[0]->ToObject());
		size_t datalen = node::Buffer::Length(info[0]->ToObject());
		
		//hash
		v8::String::Utf8Value hash(info[1]->ToString());

		//label
		char *label = NULL;
		size_t labellen = 0;
		if (!info[2]->IsUndefined()) {
			label = node::Buffer::Data(info[2]->ToObject());
			labellen = node::Buffer::Length(info[2]->ToObject());
		}

		std::string dec;
		try {
			dec = RSA_OAEP_decrypt(obj->data.internal(), *hash, (const byte*)data, datalen, label, labellen);
		}
		V8_CATCH_OPENSSL();

		V8_RETURN_BUFFER(dec);
	}

	static NAN_METHOD(GenerateRsa) {
		LOG_FUNC();

		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		int modulus = info[0]->Uint32Value();
		int publicExponent = info[1]->Uint32Value();

		if (!obj->data.generateRsa(modulus, publicExponent)) {
			Nan::ThrowError("Can not to generate RSA key");
			return;
		}

		info.GetReturnValue().Set(info.This());
	}

	static NAN_METHOD(GenerateEc) {
		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		int nidEc = info[0]->Uint32Value();

		if (!obj->data.generateEc(nidEc)) {
			Nan::ThrowError("Can not to generate EC key");
			return;
		}

		info.GetReturnValue().Set(info.This());
	}

	static NAN_GETTER(Type) {
		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());
		info.GetReturnValue().Set(Nan::New<v8::Number>(obj->data.type()));
	}

	static NAN_METHOD(ExportJWK) {
		LOG_FUNC();

		Key* key = &ObjectWrap::Unwrap<WKey>(info.Holder())->data;

		LOG_INFO("Get part of key (private/public)");
		v8::String::Utf8Value v8Part(info[0]->ToString());
		char* part = *v8Part;

		LOG_INFO("Check part");
		if (!(strcmp(part, "private") == 0 || strcmp(part, "public") == 0)) {
			Nan::ThrowError("Unknown key part in use");
			return;
		}

		LOG_INFO("Create JWK Object");
		v8::Local<v8::Object> jwk = Nan::New<v8::Object>();

		EC_KEY *ec = NULL;
		const EC_POINT *point = NULL;
		const BIGNUM *ec_private = NULL;

		BN_CTX* ctx = NULL;
		const EC_GROUP *group = NULL;
		BIGNUM *x = NULL, *y = NULL;

		try {
			switch (key->type()) {
			case EVP_PKEY_RSA:
				LOG_INFO("Convert RSA to JWK");
				Nan::Set(jwk, Nan::New("kty").ToLocalChecked(), Nan::New("RSA").ToLocalChecked());
				Nan::Set(jwk, Nan::New("n").ToLocalChecked(), bn2bin(key->internal()->pkey.rsa->n));
				Nan::Set(jwk, Nan::New("e").ToLocalChecked(), bn2bin(key->internal()->pkey.rsa->e));
				if (strcmp(part, "private") == 0) {
					Nan::Set(jwk, Nan::New("d").ToLocalChecked(), bn2bin(key->internal()->pkey.rsa->d));
					Nan::Set(jwk, Nan::New("p").ToLocalChecked(), bn2bin(key->internal()->pkey.rsa->p));
					Nan::Set(jwk, Nan::New("q").ToLocalChecked(), bn2bin(key->internal()->pkey.rsa->q));
					Nan::Set(jwk, Nan::New("dp").ToLocalChecked(), bn2bin(key->internal()->pkey.rsa->dmp1));
					Nan::Set(jwk, Nan::New("dq").ToLocalChecked(), bn2bin(key->internal()->pkey.rsa->dmq1));
					Nan::Set(jwk, Nan::New("qi").ToLocalChecked(), bn2bin(key->internal()->pkey.rsa->iqmp));
				}
				break;
			case EVP_PKEY_EC:
				LOG_INFO("Convert EC to JWK");
				ec = key->internal()->pkey.ec;
				point = EC_KEY_get0_public_key(const_cast<const EC_KEY*>(ec));
				group = EC_KEY_get0_group(ec);
				ctx = BN_CTX_new();

				x = BN_CTX_get(ctx);
				y = BN_CTX_get(ctx);
				if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x, y, ctx)) {
					BN_CTX_free(ctx);
					Nan::ThrowError("EC_POINT_get_affine_coordinates_GF2m");
					return;
				}


				Nan::Set(jwk, Nan::New("kty").ToLocalChecked(), Nan::New("EC").ToLocalChecked());
				Nan::Set(jwk, Nan::New("x").ToLocalChecked(), bn2bin(x));
				Nan::Set(jwk, Nan::New("y").ToLocalChecked(), bn2bin(y));
				if (strcmp(part, "private") == 0) {
					ec_private = EC_KEY_get0_private_key(const_cast<const EC_KEY*>(ec));
					Nan::Set(jwk, Nan::New("d").ToLocalChecked(), bn2bin(const_cast<BIGNUM*>(ec_private)));
				}
				BN_CTX_free(ctx);
				break;
			default:
				Nan::ThrowError("Unknown key type");
				return;
			}
		}
		V8_CATCH_OPENSSL();

		return info.GetReturnValue().Set(jwk);
	}

#define RSA_set_BN(v8Obj, v8Param, RsaKey, RsaKeyParam) \
	unsigned char* v8Param = (unsigned char*)node::Buffer::Data(Nan::Get(v8Obj, Nan::New(#v8Param).ToLocalChecked()).ToLocalChecked()->ToObject()); \
	RsaKey->RsaKeyParam = BN_bin2bn(v8Param, node::Buffer::Length(Nan::Get(v8Obj, Nan::New(#v8Param).ToLocalChecked()).ToLocalChecked()->ToObject()), RsaKey->RsaKeyParam);

	/*
	 * type: string - type of key (RSA | EC)
	 * part: string - key part (private | public)
	 * jwk: object - JWK data
	 */
	static NAN_METHOD(ImportJWK) {
		LOG_FUNC();

		try {
			Key* key = &ObjectWrap::Unwrap<WKey>(info.Holder())->data;

			v8::String::Utf8Value v8Type(info[0]->ToString());
			char *type = *v8Type;

			v8::String::Utf8Value v8Part(info[1]->ToString());
			char *part = *v8Part;

			v8::Local<v8::Object> v8JWK = info[2]->ToObject();

			if (strcmp(type, "RSA") == 0) {
				LOG_INFO("import RSA from JWK");
				RSA* rsa_key = RSA_new();

				LOG_INFO("set public key");
				RSA_set_BN(v8JWK, n, rsa_key, n);
				RSA_set_BN(v8JWK, e, rsa_key, e);

				if (strcmp(part, "private") == 0) {
					LOG_INFO("set private key");
					RSA_set_BN(v8JWK, d, rsa_key, d);
					RSA_set_BN(v8JWK, p, rsa_key, p);
					RSA_set_BN(v8JWK, q, rsa_key, q);
					RSA_set_BN(v8JWK, dp, rsa_key, dmp1);
					RSA_set_BN(v8JWK, dq, rsa_key, dmq1);
					RSA_set_BN(v8JWK, qi, rsa_key, iqmp);
				}

				LOG_INFO("set internal key");
				key->dispose();
				EVP_PKEY *new_key = EVP_PKEY_new();
				EVP_PKEY_assign_RSA(new_key, rsa_key);
				key->internal(new_key);
			}
			else if (strcmp(type, "EC") == 0) {
				LOG_INFO("import EC from JWK");
				EC_KEY *ec_key = EC_KEY_new();		

				LOG_INFO("set public key");
				
				int nidEc = Nan::Get(v8JWK, Nan::New("crv").ToLocalChecked()).ToLocalChecked()->Uint32Value();
				EC_GROUP *group = EC_GROUP_new_by_curve_name(nidEc);
				if (!group) {
					throw std::runtime_error("EC_GROUP_new_by_curve_name");
				}

				EC_KEY_set_group(ec_key, group);

				unsigned char* x = (unsigned char*)node::Buffer::Data(Nan::Get(v8JWK, Nan::New("x").ToLocalChecked()).ToLocalChecked()->ToObject());
				BIGNUM *_x = BN_bin2bn(x, node::Buffer::Length(Nan::Get(v8JWK, Nan::New("x").ToLocalChecked()).ToLocalChecked()->ToObject()), NULL);
				unsigned char* y = (unsigned char*)node::Buffer::Data(Nan::Get(v8JWK, Nan::New("y").ToLocalChecked()).ToLocalChecked()->ToObject());
				BIGNUM *_y = BN_bin2bn(y, node::Buffer::Length(Nan::Get(v8JWK, Nan::New("y").ToLocalChecked()).ToLocalChecked()->ToObject()), NULL);

				if (EC_KEY_set_public_key_affine_coordinates(ec_key, _x, _y) != 1) {
					BN_free(_x);
					BN_free(_y);
					EC_KEY_free(ec_key);
					THROW_OPENSSL("EC_KEY_set_public_key_affine_coordinates");
				}
				if (strcmp(part, "private") == 0) {
					LOG_INFO("set private key");
					unsigned char* d = (unsigned char*)node::Buffer::Data(Nan::Get(v8JWK, Nan::New("d").ToLocalChecked()).ToLocalChecked()->ToObject());
					BIGNUM *_d = BN_bin2bn(d, node::Buffer::Length(Nan::Get(v8JWK, Nan::New("d").ToLocalChecked()).ToLocalChecked()->ToObject()), NULL);
				
					if (EC_KEY_set_private_key(ec_key, _d) != 1) {
						BN_free(_d);
						EC_KEY_free(ec_key);
						THROW_OPENSSL("EC_KEY_set_private_key");
					}
				}

				LOG_INFO("set internal key");
				key->dispose();
				EVP_PKEY *new_key = EVP_PKEY_new();
				EVP_PKEY_assign_EC_KEY(new_key, ec_key);
				key->internal(new_key);
			}
			else {
				Nan::ThrowError("Unknown key type in use");
			}
		}
		V8_CATCH_OPENSSL();
	}

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

NAN_METHOD(Sign) {
	LOG_FUNC();

	EVP_PKEY * key = NULL;
	LOG_INFO("Unwrap Wkey");
	WKey* obj = Nan::ObjectWrap::Unwrap<WKey>(info[0]->ToObject());
	key = obj->data.internal();

	LOG_INFO("get data from buffer");
	const byte * buf = (byte*)node::Buffer::Data(info[1]);
	size_t buflen = node::Buffer::Length(info[1]);

	byte *sig = NULL;
	uint32_t siglen = 0;

	LOG_INFO("get digest name");
	v8::String::Utf8Value digestName(info[2]->ToString());
	try
	{
		sign(buf, buflen, &sig, (size_t*)&siglen, key, *digestName);
	}
	V8_CATCH_OPENSSL();

	LOG_INFO("copy signature to Buffer");
	v8::Local<v8::Object> v8Buf = Nan::NewBuffer(siglen).ToLocalChecked();
	char *pbuf = node::Buffer::Data(v8Buf);
	memcpy(pbuf, sig, siglen);

	if (sig) OPENSSL_free(sig);

	LOG_INFO("return value");
	info.GetReturnValue().Set(v8Buf);
}

NAN_METHOD(Verify) {
	LOG_FUNC();

	LOG_INFO("get key");
	EVP_PKEY * key = NULL;
	WKey* obj = Nan::ObjectWrap::Unwrap<WKey>(info[0]->ToObject());
	key = obj->data.internal();

	LOG_INFO("get data from buffer");
	const byte * buf = (byte*)node::Buffer::Data(info[1]);
	size_t buflen = node::Buffer::Length(info[1]);

	LOG_INFO("get sigdata from buffer");
	const byte * sigdata = (byte*)node::Buffer::Data(info[2]);
	size_t sigdatalen = node::Buffer::Length(info[2]);

	LOG_INFO("get digest name");
	v8::String::Utf8Value digestName(info[3]->ToString());

	int res = 0;

	try
	{
		res = verify(buf, buflen, sigdata, sigdatalen, key, *digestName);
	}
	V8_CATCH_OPENSSL();

	LOG_INFO("return value");
	info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
}

NAN_METHOD(DeriveKey) {
	LOG_FUNC();

	LOG_INFO("get private key");
	EVP_PKEY * pkey = NULL;
	WKey* obj1 = Nan::ObjectWrap::Unwrap<WKey>(info[0]->ToObject());
	pkey = obj1->data.internal();

	LOG_INFO("get public key");
	EVP_PKEY * pubkey = NULL;
	WKey* obj2 = Nan::ObjectWrap::Unwrap<WKey>(info[1]->ToObject());
	pubkey = obj2->data.internal();

	LOG_INFO("get secret size");
	size_t secret_len = info[2]->ToNumber()->Int32Value();

	std::string res;

	try
	{
		res = deriveKey(pkey, pubkey, secret_len);
	}
	V8_CATCH_OPENSSL();

	LOG_INFO("copy signature to Buffer");
	v8::Local<v8::Object> v8Buf = Nan::NewBuffer(res.length()).ToLocalChecked();
	char *pbuf = node::Buffer::Data(v8Buf);
	memcpy(pbuf, res.c_str(), res.length());

	info.GetReturnValue().Set(v8Buf);
}

NAN_MODULE_INIT(Init) {
	LOG_FUNC();

	Nan::HandleScope scope;

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	v8::Local<v8::Object> pki = Nan::New<v8::Object>();

	target->Set(Nan::New("Pki").ToLocalChecked(), pki);
	WKey::Init(pki);

	Nan::Set(pki
		, Nan::New<v8::String>("sign").ToLocalChecked()
		, Nan::New<v8::FunctionTemplate>(Sign)->GetFunction()
		);

	Nan::Set(pki
		, Nan::New<v8::String>("verify").ToLocalChecked()
		, Nan::New<v8::FunctionTemplate>(Verify)->GetFunction()
		);

	Nan::Set(pki
		, Nan::New<v8::String>("deriveKey").ToLocalChecked()
		, Nan::New<v8::FunctionTemplate>(DeriveKey)->GetFunction()
		);
}

NODE_MODULE(nodessl, Init)