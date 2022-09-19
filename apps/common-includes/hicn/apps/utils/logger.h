#pragma once

#include <glog/logging.h>

#include <iostream>

#define LoggerInfo() LOG(INFO)
#define LoggerWarn() LOG(WARNING)
#define LoggerErr() LOG(ERROR)
#define LoggerFatal() LOG(FATAL)
#define LoggerVerbose(level) VLOG((level))
#define LoggerIsOn(level) VLOG_IS_ON((level))

struct HicnLogger {
  HicnLogger() {
    // Set log level
    const char *log_level = std::getenv("LOG_LEVEL");
    if (log_level != nullptr) FLAGS_v = std::stol(std::string(log_level));

    // Enable/disable prefix
    const char *enable_log_prefix = std::getenv("ENABLE_LOG_PREFIX");
    if (enable_log_prefix != nullptr &&
        std::string(enable_log_prefix) == "OFF") {
      FLAGS_log_prefix = false;
    }

    FLAGS_colorlogtostderr = true;
  }
};

static HicnLogger logger;