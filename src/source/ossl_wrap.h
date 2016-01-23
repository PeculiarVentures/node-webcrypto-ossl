#ifndef OSSL_SSL_WRAP_H_INCLUDE
#define OSSL_SSL_WRAP_H_INCLUDE "WoW!"

#pragma message("OSSL_SSL_WRAP_H_INCLUDE")
#pragma message(OSSL_SSL_WRAP_H_INCLUDE ) // WoW!

#include "logger.h"

#include <openssl\x509.h>


// Create name for Scoped class
#define ScopedSSL_name(ossl_st)							\
	Scoped##ossl_st

// Create name for Scoped class free function
#define ScopedSSL_name_free(ossl_st)					\
	ScopedSSL_name(ossl_st)##_free

// Create wrap function for OpenSSL free functions (some OpenSSL struts use macros fo free)
#define ScopedSSL_free(ossl_st, ossl_free)							\
	void ScopedSSL_name_free(ossl_st)(void* handle){	\
		ossl_free((ossl_st*)handle);				\
	}

template <typename T, void(*CB)(void*)>
class ScopedSSL {
public:
	typedef ScopedSSL<T, CB> MyType;

	ScopedSSL() : ptr(NULL), free(CB) {}
	ScopedSSL(T* handle) : ptr(handle), free(CB) {}
	~ScopedSSL() {
		if (ptr) {
			free(ptr);
		}
	}

	static const char* TypeSSLName; // Name of wrapped OpenSSL type

	T* Get() { // return wrapped OpenSSL object
		return ptr;
	}

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
			ptr = NULL;
		}
	}

	bool isEmpty() {
		return ptr == NULL;
	}

	T* detach() {
		T* new_ptr = ptr;
		ptr = NULL;

		return new_ptr;
	}
protected:
	T* ptr;							// Point to OpenSSL structure
	void(*free)(void*handle);
};

#define ScopedSSL_create(type, free)											\
	ScopedSSL_free(type, free);													\
	using ScopedSSL_name(type) = ScopedSSL<type, &ScopedSSL_name_free(type)>;

ScopedSSL_create(BIGNUM, BN_free);
ScopedSSL_create(EVP_PKEY, EVP_PKEY_free);
ScopedSSL_create(RSA, RSA_free);
ScopedSSL_create(BIO, BIO_free);

#endif // OSSL_SSL_WRAP_H_INCLUDE