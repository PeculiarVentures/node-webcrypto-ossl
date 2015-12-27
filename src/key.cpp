#include <exception>
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

X509_SIG *PKCS8_set0_pbe(const char *pass, int passlen,
	PKCS8_PRIV_KEY_INFO *p8inf, X509_ALGOR *pbe)
{
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
	BIO* bio = BIO_new(BIO_s_mem());
	char *str;
	ERR_print_errors(bio);

	int strlen = BIO_get_mem_data(bio, &str);
	std::string res(str, strlen);

	BIO_free(bio);
	return res;
}

#define THROW_OPENSSL(text) {puts(text);throw std::exception(OPENSSL_get_errors().c_str());}

#define V8_CATCH_OPENSSL()\
	catch (std::exception& e) {Nan::ThrowError(e.what());return;}

static v8::Local<v8::Object>s2b(std::string& buf) {
	v8::Local<v8::Object> v8Buf = Nan::NewBuffer(buf.length()).ToLocalChecked();
	char *data = node::Buffer::Data(v8Buf);
	memcpy(data, buf.c_str(), buf.length());

	return v8Buf;
}

#define V8_RETURN_BUFFER(strbuf) info.GetReturnValue().Set(s2b(strbuf));

static void sign(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey, char* digestName)
{
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

	if (err) {
		BIO_free(bmd);
		THROW_OPENSSL(err);
	}

	BIO_free(bmd);
}

int verify(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey, char* digestName)
{
	/* Returned to caller */
	int result = -1;

	EVP_MD_CTX* ctx = NULL;
	char* err = NULL;

	do
	{
		ctx = EVP_MD_CTX_create();
		if (ctx == NULL) {
			err = "EVP_MD_CTX_create failed";
			break; /* failed */
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

	if (ctx) {
		EVP_MD_CTX_destroy(ctx);
		ctx = NULL;
	}

	if (err) {
		THROW_OPENSSL(err);
	}

	return result;
}

static std::string RSA_OAEP_encrypt(
	EVP_PKEY *pkey,
	char *digestName,
	const byte *data,
	size_t datalen)
{
	if (!pkey) {
		throw std::exception("pkey is NULL");
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

	if (EVP_PKEY_CTX_set_rsa_oaep_md(rctx, md) <= 0) {
		EVP_PKEY_CTX_free(rctx);
		THROW_OPENSSL("EVP_PKEY_CTX_set_rsa_oaep_md");
	}

	size_t enclen;
	if (EVP_PKEY_encrypt(rctx, NULL, &enclen, data, datalen) <= 0) {
		EVP_PKEY_CTX_free(rctx);
		THROW_OPENSSL("EVP_PKEY_encrypt");
	}

	byte *enc = (byte*)OPENSSL_malloc(enclen);

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
	size_t datalen)
{
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
		throw std::exception("Method is not implemented");
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

	BIO_free(out);

	return res;
}

static std::string k2spki(EVP_PKEY* pkey, int dataFormat) {
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

	return res;
}

class Key {
public:
	Key() {
		this->_internal = EVP_PKEY_new();
	}
	Key(EVP_PKEY *key) {
		this->_internal = key;
	}
	~Key() {
		this->dispose();
		this->_internal = NULL;
	}

	//Returns in PKCS8
	std::string writePrivateKey() {

		BIO *out;
		char *buf;
		out = BIO_new(BIO_s_mem());
		if (i2d_PKCS8PrivateKeyInfo_bio(out, this->internal()) <= 0) {
			BIO_free(out);
			throw std::exception("i2d_PKCS8PrivateKeyInfo_bio");
		}

		int buflen = BIO_get_mem_data(out, &buf);
		std::string res(buf, buflen);

		BIO_free(out);

		return res;
	}

	int type() {
		return this->internal()->type;
	}

	void dispose() {
		if (this->_internal)
			EVP_PKEY_free(this->_internal);
	}



	int generateRsa(int modulus, int publicExponent) {
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
		return this->_internal;
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

		//OAEP
		SetPrototypeMethod(tpl, "encryptRsaOAEP", encryptRsaOAEP);
		SetPrototypeMethod(tpl, "decryptRsaOAEP", decryptRsaOAEP);

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

	explicit WKey() : data(Key()) {}
	~WKey() {}

	static NAN_METHOD(New) {
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
		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		std::string res;
		int format = DATA_FORMAT_DER;
		char *formatStr = *v8::String::Utf8Value(info[0]->ToString());
		if (strcmp(formatStr, "pem") == 0)
			format = DATA_FORMAT_PEM;

		try {
			if (info[1]->IsUndefined()) {
				//no crypto
				res = k2pkcs8(obj->data.internal(), format, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
			}
			else {
				//crypto
				char *pass = *v8::String::Utf8Value(info[1]->ToString());
				int passlen = info[1]->ToString()->Length();
				byte *salt = (byte *)node::Buffer::Data(info[2]->ToObject());
				int saltlen = node::Buffer::Length(info[2]->ToObject());
				int iter = info[3]->ToNumber()->Int32Value();

				res = k2pkcs8(obj->data.internal(), format, EVP_aes_256_gcm(), "", pass, passlen, salt, saltlen, iter);
			}
		}
		V8_CATCH_OPENSSL();

		V8_RETURN_BUFFER(res);
	}

	/*
	format: String
	*/
	static NAN_METHOD(WriteSPKI) {
		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		std::string res;
		int format = DATA_FORMAT_DER;
		char *formatStr = *v8::String::Utf8Value(info[0]->ToString());
		if (strcmp(formatStr, "pem") == 0)
			format = DATA_FORMAT_PEM;
		try {
			res = k2spki(obj->data.internal(), format);
		}
		V8_CATCH_OPENSSL();

		V8_RETURN_BUFFER(res);
	}

	/*
	data: Buffer
	hash: String
	*/
	static NAN_METHOD(encryptRsaOAEP) {
		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		//data
		char *data = node::Buffer::Data(info[0]->ToObject());
		size_t datalen = node::Buffer::Length(info[0]->ToObject());
		//hash
		char *hash = *v8::String::Utf8Value(info[1]->ToString());

		std::string enc;
		try {
			enc = RSA_OAEP_encrypt(obj->data.internal(), hash, (const byte*)data, datalen);
		}
		V8_CATCH_OPENSSL();

		V8_RETURN_BUFFER(enc);
	}

	/*
	data: Buffer
	hash: String
	*/
	static NAN_METHOD(decryptRsaOAEP) {
		WKey* obj = ObjectWrap::Unwrap<WKey>(info.Holder());

		//data
		char *data = node::Buffer::Data(info[0]->ToObject());
		size_t datalen = node::Buffer::Length(info[0]->ToObject());
		//hash
		char *hash = *v8::String::Utf8Value(info[1]->ToString());

		std::string dec;
		try {
			dec = RSA_OAEP_decrypt(obj->data.internal(), hash, (const byte*)data, datalen);
		}
		V8_CATCH_OPENSSL();

		V8_RETURN_BUFFER(dec);
	}

	static NAN_METHOD(GenerateRsa) {
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

	static inline Nan::Persistent<v8::Function> & constructor() {
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}
};

NAN_METHOD(Sign) {

	EVP_PKEY * key = NULL;
	WKey* obj = Nan::ObjectWrap::Unwrap<WKey>(info[0]->ToObject());
	key = obj->data.internal();

	//get data from buffer
	const byte * buf = (byte*)node::Buffer::Data(info[1]);
	size_t buflen = node::Buffer::Length(info[1]);

	byte *sig = NULL;
	uint32_t siglen = 0;

	//get digest name
	char * digestName = (*v8::String::Utf8Value(info[2]->ToString()));

	try
	{
		sign(buf, buflen, &sig, (size_t*)&siglen, key, digestName);
	}
	V8_CATCH_OPENSSL();

	v8::Local<v8::Object> v8Buf = Nan::NewBuffer(siglen).ToLocalChecked();
	char *pbuf = node::Buffer::Data(v8Buf);
	memcpy(pbuf, sig, siglen);

	if (sig) OPENSSL_free(sig);

	info.GetReturnValue().Set(v8Buf);
}

NAN_METHOD(Verify) {

	//get key
	EVP_PKEY * key = NULL;
	WKey* obj = Nan::ObjectWrap::Unwrap<WKey>(info[0]->ToObject());
	key = obj->data.internal();

	//get data from buffer
	const byte * buf = (byte*)node::Buffer::Data(info[1]);
	size_t buflen = node::Buffer::Length(info[1]);

	//get sigdata from buffer
	const byte * sigdata = (byte*)node::Buffer::Data(info[2]);
	size_t sigdatalen = node::Buffer::Length(info[2]);

	//get digest name
	char * digestName = (*v8::String::Utf8Value(info[3]->ToString()));

	int res = 0;

	try
	{
		res = verify(buf, buflen, sigdata, sigdatalen, key, digestName);
	}
	V8_CATCH_OPENSSL();

	info.GetReturnValue().Set(Nan::New<v8::Boolean>(res));
}


NAN_MODULE_INIT(Init) {
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

}

NODE_MODULE(nodessl, Init)