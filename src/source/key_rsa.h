#ifndef OSSL_KEY_RSA_H_INCLUDE
#define OSSL_KEY_RSA_H_INCLUDE

#include "common.h"
#include "excep.h"

Handle<ScopedEVP_PKEY> RSA_generate(int modulus, int publicExponent);
v8::Local<v8::Object> RSA_export_jwk(EVP_PKEY *pkey, int &key_type);

#endif // OSSL_KEY_RSA_H_INCLUDE