#ifndef OSSL_KEY_RSA_H_INCLUDE
#define OSSL_KEY_RSA_H_INCLUDE

#include "common.h"
#include "excep.h"

Handle<ScopedEVP_PKEY> generateRsa(int modulus, int publicExponent);

#endif // OSSL_KEY_RSA_H_INCLUDE