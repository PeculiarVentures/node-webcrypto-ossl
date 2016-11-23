#include "common.h"

Handle<ScopedHMAC> ScopedHMAC::generate(int &length) {
	LOG_FUNC();

	int lengthBytes = bit2byte(length);
	Handle<std::string> hValue(new std::string());
	if (!lengthBytes)
		THROW_ERROR("Size of key too small");
	hValue->resize(lengthBytes);
	byte *value = (byte*)hValue->c_str();
	RAND_bytes(value, lengthBytes);

	Handle<ScopedHMAC> hHMAC(new ScopedHMAC());
	hHMAC->value = hValue;
	return hHMAC;
}