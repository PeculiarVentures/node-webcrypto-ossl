#include "common.h"

#include <openssl/hmac.h>

Handle<std::string> ScopedHMAC::sign(Handle<std::string> hMsg, const EVP_MD *md) {
	LOG_FUNC();

	if (!md)
		THROW_ERROR("Parameter md is empty");
	size_t resLen = EVP_MD_size(md);

	Handle<std::string> res(new std::string());
	res->resize(resLen);

	unsigned int outLen;
	if (!HMAC(md, this->value->c_str(), (int)this->value->length(), (unsigned char*)hMsg->c_str(),
		(size_t)hMsg->length(), (unsigned char*)res->c_str(), &outLen)) {
		THROW_OPENSSL("HMAC");
	}

	if (outLen != resLen)
		THROW_ERROR("Signature length is not equal to actual HMAC length");

	return res;

}
bool ScopedHMAC::verify(Handle<std::string> hMsg, const EVP_MD *md, Handle<std::string> signature) {
	LOG_FUNC();

	Handle<std::string> signature2 = this->sign(hMsg, md);

	return !signature->compare(*signature2.get());
}
