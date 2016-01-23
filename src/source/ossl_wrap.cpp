#include "ossl_wrap.h"

ScopedSSL_free(BIGNUM, BN_free);
ScopedSSL_free(EVP_PKEY, EVP_PKEY_free);
ScopedSSL_free(RSA, RSA_free);
ScopedSSL_free(BIO, BIO_free);