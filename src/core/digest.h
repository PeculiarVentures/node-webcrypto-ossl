#ifndef OSSL_CORE_DIGEST_H_INCLUDE
#define OSSL_CORE_DIGEST_H_INCLUDE

#include "define.h"
#include "scoped_ssl.h"

Handle<std::string> digest(const EVP_MD *md, Handle<std::string> hBuffer);

#endif // OSSL_CORE_DIGEST_H_INCLUDE
