/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#pragma once

#include <hicn/transport/interfaces/global_conf_interface.h>
#include <hicn/transport/utils/singleton.h>

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <system_error>

namespace libconfig {
class Setting;
}

namespace transport {
namespace core {

/**
 * Class holding workflow for global configuration.
 * This class does not contains the actual configuration, which is rather stored
 * inside the modules to be configured. This class contains the handlers to call
 * for getting/setting the configurations and to parse the corresponding
 * sections of the configuration file. Each class register 3 callbacks: one to
 * parse conf section and 2 to set/get the configuration through programming
 * interface.
 */
class GlobalConfiguration : public utils::Singleton<GlobalConfiguration> {
  static const constexpr char *conf_file = "TRANSPORT_CONFIG";
  friend class utils::Singleton<GlobalConfiguration>;

 public:
  /**
   * This callback will be called by GlobalConfiguration in
   *
   */
  using ParserCallback = std::function<void(const libconfig::Setting &config,
                                            std::error_code &ec)>;
  using GetCallback =
      std::function<void(interface::global_config::ConfigurationObject &object,
                         std::error_code &ec)>;

  using SetCallback = std::function<void(
      const interface::global_config::ConfigurationObject &object,
      std::error_code &ec)>;

  ~GlobalConfiguration() = default;

 public:
  void parseConfiguration(const std::string &path);

  void registerConfigurationParser(const std::string &key,
                                   const ParserCallback &parser);

  void registerConfigurationSetter(const std::string &key,
                                   const SetCallback &set_callback);
  void registerConfigurationGetter(const std::string &key,
                                   const GetCallback &get_callback);

  void unregisterConfigurationParser(const std::string &key);

  void unregisterConfigurationSetter(const std::string &key);

  void unregisterConfigurationGetter(const std::string &key);

  void getConfiguration(
      interface::global_config::ConfigurationObject &configuration_object,
      std::error_code &ec);
  void setConfiguration(
      const interface::global_config::ConfigurationObject &configuration_object,
      std::error_code &ec);

 private:
  GlobalConfiguration();
  std::string conf_file_path_;
  bool parseTransportConfig(const std::string &path);

 private:
  std::mutex cp_mtx_;
  using ParserPair = std::pair<bool, ParserCallback>;
  std::map<std::string, ParserPair> configuration_parsers_;
  std::map<std::string, GetCallback> configuration_getters_;
  std::map<std::string, SetCallback> configuration_setters_;
};

}  // namespace core
}  // namespace transport