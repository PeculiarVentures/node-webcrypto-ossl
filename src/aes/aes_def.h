#ifndef OSSL_AES_DEF_H_INCLUDE
#define OSSL_AES_DEF_H_INCLUDE

#include "../core/common.h"

#define JWK_KTY_AES "oct"

#define JWK_ATTR_K "k"

class ScopedAES {
public:
	ScopedAES() {}
	ScopedAES(Handle<std::string> aes): value(aes) {}
	~ScopedAES() {}

	Handle<std::string> value;

	static Handle<ScopedAES> generate(int &keySize);
	
	Handle<std::string> encrypt(Handle<ScopedAES> hKey, Handle<std::string> hMsg, Handle<std::string> hIv);
	Handle<std::string> decrypt(Handle<ScopedAES> hKey, Handle<std::string> hMsg, Handle<std::string> hIv);

	Handle<std::string> wrap();
	Handle<std::string> unwrap();
};

#endif // OSSL_AES_DEF_H_INCLUDE