#ifndef OSSL_RSA_COMMON_H_INCLUDE
#define OSSL_RSA_COMMON_H_INCLUDE

#include "../core/common.h"

#include "rsa_jwk.h"
#include "rsa_pkcs1.h"
#include "rsa_oaep.h"

Handle<ScopedEVP_PKEY> RSA_generate(int modulus, int publicExponent);

#endif // OSSL_RSA_COMMON_H_INCLUDE