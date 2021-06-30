/*
 * Copyright (c) 2017-2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define GLOG_CUSTOM_PREFIX_SUPPORT 1
#include <glog/logging.h>
#undef GLOG_CUSTOM_PREFIX_SUPPORT

#include <core/global_configuration.h>
#include <hicn/transport/config.h>
#include <hicn/transport/utils/log.h>

#include <iomanip>
#include <iostream>
#include <libconfig.h++>

namespace utils {

#define _(class_name, macro_name) \
  std::ostream &CLASS_NAME(class_name)::getStream() { return macro_name; }
foreach_log_level
#undef _

    class LogConfiguration {
  static constexpr char log_config_section[] = "log";
#define LOG_NAME                                  \
  "Libhicntransport-" HICNTRANSPORT_VERSION_MAJOR \
  "." HICNTRANSPORT_VERSION_MINOR "." HICNTRANSPORT_VERSION_REVISION
  static constexpr char log_name[] = LOG_NAME;

#define foreach_log_config        \
  _(bool, logtostderr, true)      \
  _(bool, alsologtostderr, false) \
  _(bool, colorlogtostderr, true) \
  _(int32_t, stderrthreshold, 2)  \
  _(int32_t, minloglevel, 0)      \
  _(bool, log_prefix, true)       \
  _(std::string, log_dir, "")     \
  _(int32_t, v, 1)                \
  _(std::string, vmodule, "")     \
  _(int32_t, max_log_size, 5)     \
  _(bool, stop_logging_if_full_disk, true)

 public:
  LogConfiguration() {
    auto &conf = transport::core::GlobalConfiguration::getInstance();

    using namespace std::placeholders;
    conf.registerConfigurationParser(
        log_config_section,
        std::bind(&LogConfiguration::parseLogConfiguration, this, _1, _2));
  }

 private:
  void parseLogConfiguration(const libconfig::Setting &log_config,
                             std::error_code &ec) {
#define _(type, name, default)                                      \
  type _##name = default;                                           \
                                                                    \
  if (log_config.exists(#name)) {                                   \
    log_config.lookupValue(#name, _##name);                         \
    VLOG(2) << "Setting log config " << #name << " to " << _##name; \
                                                                    \
    FLAGS_##name = _##name;                                         \
  } else {                                                          \
    VLOG(2) << "Log config " << #name << " do not exists";          \
  }
    foreach_log_config
#undef _

        google::InitGoogleLogging(log_name);
  }
};

constexpr char LogConfiguration::log_config_section[];
constexpr char LogConfiguration::log_name[];

LogConfiguration log_conf = LogConfiguration();

}  // namespace utils
