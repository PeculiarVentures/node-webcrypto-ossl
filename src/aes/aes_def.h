#ifndef OSSL_AES_DEF_H_INCLUDE
#define OSSL_AES_DEF_H_INCLUDE

#include "../core/common.h"

#define JWK_KTY_AES "oct"

#define JWK_ATTR_K "k"

class ScopedAES {
public:
	ScopedAES() {}
	ScopedAES(Handle<ScopedBIO> aes): value(aes) {}
	~ScopedAES() {}

	Handle<ScopedBIO> value;

	static Handle<ScopedAES> ScopedAES::generate(int &keySize);
	
	Handle<ScopedBIO> encrypt(Handle<ScopedAES> hKey, Handle<ScopedBIO> hMsg, Handle<ScopedBIO> hIv);
	Handle<ScopedBIO> decrypt(Handle<ScopedAES> hKey, Handle<ScopedBIO> hMsg, Handle<ScopedBIO> hIv);

	Handle<ScopedBIO> wrap();
	Handle<ScopedBIO> unwrap();
};

#endif // OSSL_AES_DEF_H_INCLUDE