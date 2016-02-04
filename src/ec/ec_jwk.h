#ifndef OSSL_EC_JWK_H_INCLUDE
#define OSSL_EC_JWK_H_INCLUDE

#include "../core/common.h"

#define JWK_KTY_EC "EC"

#define JWK_ATTR_X "x"
#define JWK_ATTR_Y "y"
#define JWK_ATTR_D "d"
#define JWK_ATTR_CRV "crv"

class JwkEc {
public:
	JwkEc() : kty(JWK_KTY_EC) {}
	const char *kty;
	ScopedBIGNUM x;
	ScopedBIGNUM y;
	ScopedBIGNUM d;
	int crv;
	int type;

	static Handle<JwkEc> From(Handle<ScopedEVP_PKEY> pkey, int &key_type);
	Handle<ScopedEVP_PKEY> To(int &key_type);
};

#endif // OSSL_EC_JWK_H_INCLUDE