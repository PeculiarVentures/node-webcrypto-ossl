#ifndef OSSL_RSA_JWK_H_INCLUDE
#define OSSL_RSA_JWK_H_INCLUDE

#include "../core/common.h"

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

class JwkRsa {
public:
	JwkRsa() : kty(JWK_KTY_RSA) {}
	const char *kty;
	ScopedBIGNUM n;
	ScopedBIGNUM e;
	ScopedBIGNUM d;
	ScopedBIGNUM p;
	ScopedBIGNUM q;
	ScopedBIGNUM dp;
	ScopedBIGNUM dq;
	ScopedBIGNUM qi;
	int type;

	static Handle<JwkRsa> From(Handle<ScopedEVP_PKEY> pkey, int &key_type);
	Handle<ScopedEVP_PKEY> To(int &key_type);
};

#endif // OSSL_RSA_JWK_H_INCLUDE