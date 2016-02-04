#ifndef OSSL_EC_GEN_H_INCLUDE
#define OSSL_EC_GEN_H_INCLUDE

#include "../core/common.h"

Handle<ScopedEVP_PKEY> EC_generate(int &nidEc);

#endif // OSSL_EC_GEN_H_INCLUDE