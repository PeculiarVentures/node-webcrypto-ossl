#ifndef OSSL_COMMON_H_INCLUDE
#define OSSL_COMMON_H_INCLUDE

#include <memory>
#include <nan.h>

template<typename T> using  Handle = std::shared_ptr<T>;

//Key type
#define NODESSL_KT_PUBLIC 0
#define NODESSL_KT_PRIVATE 1

#include "logger.h"
#include "ossl_wrap.h"
#include "excep.h"

v8::Local<v8::Object> bn2buf(BIGNUM* bn);
Handle<ScopedBIO> KEY_export(EVP_PKEY *pkey, int(*i2d_function_bio)(BIO *bp, EVP_PKEY *key));

Handle<ScopedBIO> KEY_export_spki(EVP_PKEY *pkey);
Handle<ScopedBIO> KEY_export_pkcs8(EVP_PKEY *pkey);
Handle<ScopedEVP_PKEY> KEY_import_spki(BIO *in);
Handle<ScopedEVP_PKEY> KEY_import_pkcs8(BIO *in);

// #include "key_rsa.h"

#endif // OSSL_COMMON_H_INCLUDE