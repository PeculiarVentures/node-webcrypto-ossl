#ifndef OSSL_NODE_COMMON_H_INCLUDE
#define OSSL_NODE_COMMON_H_INCLUDE

#include "../core/common.h"
#include "../rsa/common.h"
#include "../ec/common.h"

v8::Local<v8::Object> bn2buf(BIGNUM* bn);
Handle<ScopedBIO> v8Buffer_to_ScopedBIO(v8::Local<v8::Value> v8Buffer);
Handle<ScopedBIO> v8Buffer_to_ScopedBIO(v8::Local<v8::Object> v8Buffer);
v8::Local<v8::Object> ScopedBIO_to_v8Buffer(Handle<ScopedBIO> bio);

#include "./async_rsa.h"
#include "./async_ec.h"
#include "./w_key.h"

#endif // OSSL_NODE_COMMON_H_INCLUDE