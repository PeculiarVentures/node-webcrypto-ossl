#include "aes_def.h"

#include <openssl/rand.h>

Handle<ScopedAES> ScopedAES::generate(int &keySize){
	LOG_FUNC();

	Handle<std::string> hValue(new std::string());
	hValue->resize(keySize);
	byte *value = (byte*)hValue->c_str();
	RAND_bytes(value, keySize);
	
    Handle<ScopedAES> hAes(new ScopedAES());
    hAes->value = hValue;
	return hAes;
}