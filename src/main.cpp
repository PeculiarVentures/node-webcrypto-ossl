#include "node/common.h"

NAN_MODULE_INIT(InitModule) {

	Nan::HandleScope scope;

	OPENSSL_init();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	WKey::Init(target);
	WAes::Init(target);
	WCore::Init(target);

}

NODE_MODULE(nodessl, InitModule);