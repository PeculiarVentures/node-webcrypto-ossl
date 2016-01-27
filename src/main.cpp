#include "node/common.h"

NAN_MODULE_INIT(InitModule) {

	Nan::HandleScope scope;

	OPENSSL_init();
	OpenSSL_add_all_algorithms();

	WKey::Init(target);

}

NODE_MODULE(nodessl, InitModule);