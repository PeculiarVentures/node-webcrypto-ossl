#include "logger.h"

#include <string>

FunctionLog::FunctionLog(const char *name) {
	name_ = std::string(name);

	std::string res = "BEGIN: " + name_;
	LOG_INFO(res.c_str());
}

FunctionLog::~FunctionLog() {
	std::string res = "END:   " + name_;
	LOG_INFO(res.c_str());
}