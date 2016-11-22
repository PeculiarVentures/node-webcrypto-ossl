#include "digest.h"

#include "excep.h"

Handle<std::string> digest(const EVP_MD *md, Handle<std::string> hBuffer) {
	LOG_FUNC();

	if (!md) {
		THROW_ERROR("EVP_MD is NULL");
	}

	byte* buf = (byte*)hBuffer->c_str();
	int buflen = (int)hBuffer->length();

	Handle<std::string> hDigest(new std::string());
	hDigest->resize(md->md_size);
	byte* digest = (byte*)hDigest->c_str();

	if (!EVP_Digest(buf, buflen, digest, NULL, md, NULL)) {
		THROW_OPENSSL("EVP_Digest");
	}

	return hDigest;
}