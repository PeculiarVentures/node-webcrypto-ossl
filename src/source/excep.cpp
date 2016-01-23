#include "excep.h"

std::string OPENSSL_get_errors() {
	LOG_FUNC();

	ScopedBIO bio = BIO_new(BIO_s_mem());
	char *str;
	ERR_print_errors(bio.Get());

	int strlen = BIO_get_mem_data(bio.Get(), &str);
	std::string res(str, strlen);

	BIO_free(bio.Get());
	return res;
}