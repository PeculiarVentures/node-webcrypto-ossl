#ifndef OSSL_RSA_JWK_H_INCLUDE
#define OSSL_RSA_JWK_H_INCLUDE

#include "common.h"

#define JWK_KTY_RSA "RSA"

#define JWK_ATTR_KTY "kty"
#define JWK_ATTR_N "n"
#define JWK_ATTR_E "e"
#define JWK_ATTR_D "d"
#define JWK_ATTR_P "p"
#define JWK_ATTR_Q "q"
#define JWK_ATTR_DP "dp"
#define JWK_ATTR_DQ "dq"
#define JWK_ATTR_QI "qi"

typedef struct JWK_RSA_st
{
	char *kty = JWK_KTY_RSA;
	ScopedBIGNUM n;
	ScopedBIGNUM e;
	ScopedBIGNUM d;
	ScopedBIGNUM p;
	ScopedBIGNUM q;
	ScopedBIGNUM dp;
	ScopedBIGNUM dq;
	ScopedBIGNUM qi;
	int type;
} JWK_RSA;

JWK_RSA* JWK_RSA_new();
void JWK_RSA_free();

ScopedSSL_create(JWK_RSA, JWK_RSA_free);

Handle<ScopedJWK_RSA> RSA_export_jwk(EVP_PKEY *pkey, int &key_type);
Handle<ScopedEVP_PKEY> RSA_import_jwk(Handle<ScopedJWK_RSA> hJwk, int &key_type);

#endif // OSSL_RSA_JWK_H_INCLUDE