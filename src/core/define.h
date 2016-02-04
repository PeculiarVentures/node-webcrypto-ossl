#ifndef OSSL_CORE_DEFINE_H_INCLUDE
#define OSSL_CORE_DEFINE_H_INCLUDE

#include <memory>

template<typename T> using  Handle = std::shared_ptr<T>;

//Key type
#define NODESSL_KT_PUBLIC 0
#define NODESSL_KT_PRIVATE 1

#ifndef byte
typedef unsigned char byte;
#endif // byte

#endif // OSSL_CORE_DEFINE_H_INCLUDE