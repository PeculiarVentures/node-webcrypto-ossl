#ifndef OSSL_CORE_SCOPED_SSL_H_INCLUDE
#define OSSL_CORE_SCOPED_SSL_H_INCLUDE

#include "logger.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

// Create name for Scoped class
#define ScopedSSL_name(ossl_st)							\
	Scoped##ossl_st

// Create name for Scoped class free function
#define ScopedSSL_name_free(ossl_st)					\
	Scoped##ossl_st##_free

#define ScopedSSL_free_define(ossl_st, ossl_free)							\
	void ScopedSSL_name_free(ossl_st)(void* handle);

// Create wrap function for OpenSSL free functions (some OpenSSL struts use macros for free)
#define ScopedSSL_free(ossl_st, ossl_free)							\
	void ScopedSSL_name_free(ossl_st)(void* handle){				\
		ossl_free((ossl_st*)handle);								\
	}

template <typename T, void(*CB)(void*)>
class ScopedSSL {
public:
	typedef ScopedSSL<T, CB> MyType;

	ScopedSSL() : ptr(nullptr), free(CB) {}
	ScopedSSL(T* handle) : ptr(handle), free(CB) {}
	explicit ScopedSSL(MyType &handle) : ptr(handle.Get()), free(CB) {
		handle.ptr = nullptr;
	}
	~ScopedSSL() {
		if (ptr) {
			free(ptr);
		}
	}

	static const char* TypeSSLName; // Name of wrapped OpenSSL type

	T* Get() { // return wrapped OpenSSL object
		return ptr;
	}

	/*Handle<MyType> Handle() {
		return Handle<MyType>(new MyType((*this)));
	}*/

	MyType& operator=(T* _Right)
	{	// take resource from _Right
		LOG_FUNC();

		if (ptr != _Right) {
			dispose();
			ptr = _Right;
		}
		return (*this);
	}

	void dispose() { // clear wrapped OpenSSL object
		LOG_FUNC();

		if (ptr) {
			free(ptr);
			ptr = nullptr;
		}
	}

	void unref() {
		this->ptr = nullptr;
	}

	bool isEmpty() {
		return ptr == nullptr;
	}

	T* detach() {
		T* new_ptr = ptr;
		ptr = nullptr;
		return new_ptr;
	}
protected:
	T* ptr;							// Point to OpenSSL structure
	void(*free)(void*handle);
};

#define ScopedSSL_create(type, free)											\
	ScopedSSL_free_define(type, free);											\
	using ScopedSSL_name(type) = ScopedSSL<type, &ScopedSSL_name_free(type)>;

ScopedSSL_create(BIGNUM, BN_free);
ScopedSSL_create(EVP_PKEY, EVP_PKEY_free);
ScopedSSL_create(RSA, RSA_free);
ScopedSSL_create(EC_KEY, EC_KEY_free);
ScopedSSL_create(BIO, BIO_free);
ScopedSSL_create(EVP_PKEY_CTX, EVP_PKEY_CTX_free);
ScopedSSL_create(BN_CTX, BN_CTX_free);
ScopedSSL_create(ECDSA_SIG, ECDSA_SIG_free);
ScopedSSL_create(EC_GROUP, EC_GROUP_free);
ScopedSSL_create(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
ScopedSSL_create(EVP_MD_CTX, EVP_MD_CTX_destroy);

#endif // OSSL_CORE_SCOPED_SSL_H_INCLUDE