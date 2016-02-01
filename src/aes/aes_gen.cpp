#include "aes_def.h"

#include <openssl/rand.h>

Handle<ScopedAES> ScopedAES::generate(int &keySize){
	LOG_FUNC();

	Handle<std::string> hValue(new std::string());
	hValue->resize(keySize);
	unsigned char *value = (unsigned char*)hValue->c_str();
	RAND_bytes(value, keySize);
	
	return Handle<ScopedAES>(new ScopedAES(hValue));
}