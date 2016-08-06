#ifndef OSSL_CORE_BN_H_INCLUDE
#define OSSL_CORE_BN_H_INCLUDE

#include "define.h"
#include <openssl/bn.h>
#include <stdint.h>

int BN_bn2bin_padded(uint8_t *out, size_t len, const BIGNUM *in);

#endif // OSSL_CORE_BN_H_INCLUDE