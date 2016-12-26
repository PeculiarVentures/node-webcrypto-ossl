#ifndef OSSL_NODE_COMMON_H_INCLUDE
#define OSSL_NODE_COMMON_H_INCLUDE

#include "../core/common.h"
#include "../rsa/common.h"
#include "../ec/common.h"
#include "../hmac/common.h"
#include "../pbkdf2/common.h"

v8::Local<v8::Object> bn2buf(BIGNUM* bn);
Handle<std::string> v8Buffer_to_String(v8::Local<v8::Value> v8Buffer);
Handle<std::string> v8Buffer_to_String(v8::Local<v8::Object> v8Buffer);
v8::Local<v8::Object> String_to_v8Buffer(Handle<std::string> hBuffer);

#include "./async_rsa.h"
#include "./async_ec.h"
#include "./async_core.h"
#include "./w_key.h"
#include "./w_aes.h"
#include "./w_hmac.h"
#include "./w_pbkdf2.h"
#include "./w_core.h"

#endif // OSSL_NODE_COMMON_H_INCLUDE