#ifndef OSSL_HMAC_H_INCLUDE
#define OSSL_HMAC_H_INCLUDE

#include "../core/common.h"
#include <openssl/rand.h>

class ScopedHMAC {
public:
	ScopedHMAC() : type(EVP_PKEY_HMAC) {}
	ScopedHMAC(Handle<std::string> hmac) : value(hmac), type(EVP_PKEY_HMAC) {}
	~ScopedHMAC() {}

	Handle<std::string> value;

	static Handle<ScopedHMAC> generate(int &length);

	Handle<std::string> sign(Handle<std::string> hMsg, const EVP_MD *md);
	bool verify(Handle<std::string> hMsg, const EVP_MD *md, Handle<std::string> signature);

	int type;
};

#endif // OSSL_HMAC_H_INCLUDE