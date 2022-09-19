#pragma once

#include <glog/logging.h>

#include <iostream>

#define LoggerInfo() LOG(INFO)
#define LoggerWarn() LOG(WARNING)
#define LoggerErr() LOG(ERROR)
#define LoggerFatal() LOG(FATAL)
#define LoggerVerbose(level) VLOG((level))
#define LoggerIsOn(level) VLOG_IS_ON((level))

struct Logger {
  Logger() {
    const char *log_level = std::getenv("LOG_LEVEL");
    if (log_level != nullptr) FLAGS_v = std::stol(std::string(log_level));
  }
};

static Logger logger;