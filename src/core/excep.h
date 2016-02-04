#ifndef OSSL_CORE_EXCEP_H_INCLUDE
#define OSSL_CORE_EXCEP_H_INCLUDE

#include <stdexcept>
#include <openssl/err.h>

#include "logger.h"

std::string OPENSSL_get_errors();

#define LOG_ERROR(text) \
	LOG_INFO("ERROR: %s\n%s", text, __FUNCTION__);

#define THROW_ERROR(text) \
	{LOG_ERROR(text); throw std::runtime_error(text);}

#define THROW_OPENSSL(text) \
	{LOG_ERROR(text);throw std::runtime_error(OPENSSL_get_errors().c_str());}

#endif // OSSL_CORE_EXCEP_H_INCLUDE