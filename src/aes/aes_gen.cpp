#include "aes_def.h"

#include <openssl/rand.h>

Handle<ScopedAES> ScopedAES::generate(int &keySize){
	LOG_FUNC();

	byte *rnd = (byte*)OPENSSL_malloc(keySize);
	RAND_bytes(rnd, keySize);
	
	Handle<ScopedBIO> value(new ScopedBIO(BIO_new_mem_buf(rnd, keySize)));
	return Handle<ScopedAES>(new ScopedAES(value));
}