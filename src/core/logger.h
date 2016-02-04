#ifndef OSSL_CORE_LOGGER_H_INCLUDE
#define OSSL_CORE_LOGGER_H_INCLUDE

#include <string>

// #define V8_DEBUG

class FunctionLog {
public:
	explicit FunctionLog(const char *name);
	~FunctionLog();

protected:
	std::string name_;
};

#ifdef V8_DEBUG
#define LOG_INFO(name, ...) \
	fprintf(stdout, name, __VA_ARGS__); puts("");

#define LOG_FUNC() \
	FunctionLog __v8_func(__FUNCTION__);

#else

#define LOG_INFO(name, ...){}
#define LOG_FUNC(){}

#endif

#endif // OSSL_CORE_LOGGER_H_INCLUDE