#include "source/w_key.h"

NAN_MODULE_INIT(InitModule) {

	Nan::HandleScope scope;

	WKey::Init(target);

}

NODE_MODULE(nodessl, InitModule);