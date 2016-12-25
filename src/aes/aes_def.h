#ifndef OSSL_AES_DEF_H_INCLUDE
#define OSSL_AES_DEF_H_INCLUDE

#include "../core/common.h"

#define JWK_KTY_AES "oct"

#define JWK_ATTR_K "k"

class ScopedAES {
public:
	ScopedAES() {}
	ScopedAES(Handle<std::string> aes): value(aes), type(EVP_PKEY_NONE) {}
	~ScopedAES() {}

	Handle<std::string> value;

	static Handle<ScopedAES> generate(int &keySize);
	
	Handle<std::string> encryptCbc(Handle<std::string> hMsg, Handle<std::string> hIv);
	Handle<std::string> decryptCbc(Handle<std::string> hMsg, Handle<std::string> hIv);
	Handle<std::string> encryptGcm(Handle<std::string> hMsg, Handle<std::string> hIv, Handle<std::string> hAad, int tagSize);
	Handle<std::string> decryptGcm(Handle<std::string> hMsg, Handle<std::string> hIv, Handle<std::string> hAad, int tagSize);

	Handle<std::string> wrap(Handle<std::string> data);
	Handle<std::string> unwrap(Handle<std::string> encKey);

	int type;
};

#endif // OSSL_AES_DEF_H_INCLUDE