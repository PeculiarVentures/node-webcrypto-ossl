#ifndef OSSL_CORE_COMMON_H_INCLUDE
#define OSSL_CORE_COMMON_H_INCLUDE

#ifdef _WIN32
#define __WINCRYPT_H__
#endif

#include <nan.h>

#include "logger.h"
#include "scoped_ssl.h"
#include "excep.h"
#include "key_exp.h"
#include "digest.h"
#include "bn.h"
#include <openssl/bn.h>

#endif // OSSL_CORE_COMMON_H_INCLUDE
