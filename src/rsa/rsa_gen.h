#ifndef OSSL_RSA_GEN_H_INCLUDE
#define OSSL_RSA_GEN_H_INCLUDE

Handle<ScopedEVP_PKEY> RSA_generate(int modulus, int publicExponent);

#endif // OSSL_RSA_GEN_H_INCLUDE