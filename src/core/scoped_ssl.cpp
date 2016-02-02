#include "scoped_ssl.h"

ScopedSSL_free(BIGNUM, BN_free);
ScopedSSL_free(EVP_PKEY, EVP_PKEY_free);
ScopedSSL_free(RSA, RSA_free);
ScopedSSL_free(EC_KEY, EC_KEY_free);
ScopedSSL_free(BIO, BIO_free);
ScopedSSL_free(EVP_PKEY_CTX, EVP_PKEY_CTX_free);
ScopedSSL_free(BN_CTX, BN_CTX_free);
ScopedSSL_free(ECDSA_SIG, ECDSA_SIG_free);
ScopedSSL_free(EC_GROUP, EC_GROUP_free);
ScopedSSL_free(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
ScopedSSL_free(EVP_MD_CTX, EVP_MD_CTX_destroy);