#ifndef OSSL_CORE_DEFINE_H_INCLUDE
#define OSSL_CORE_DEFINE_H_INCLUDE

#include <memory>

template<typename T> using  Handle = std::shared_ptr<T>;

template <typename T> T bit2byte(T x) {
	return (x / 8) + (7 + (x % 8)) / 8;
}

//Key type
#define NODESSL_KT_PUBLIC 0
#define NODESSL_KT_PRIVATE 1

#ifndef byte
typedef unsigned char byte;
#endif // byte

#endif // OSSL_CORE_DEFINE_H_INCLUDE