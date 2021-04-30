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

#include <core/global_configuration.h>
#include <hicn/transport/core/connector.h>
#include <hicn/transport/utils/log.h>

#include <libconfig.h++>
#include <map>

namespace transport {
namespace core {

GlobalConfiguration::GlobalConfiguration() {}

bool GlobalConfiguration::parseTransportConfig(const std::string& path) {
  using namespace libconfig;
  Config cfg;

  try {
    cfg.readFile(path.c_str());
  } catch (const FileIOException& fioex) {
    TRANSPORT_LOGE("I/O error while reading file: %s", fioex.what());
    return false;
  } catch (const ParseException& pex) {
    TRANSPORT_LOGE("Parse error at %s:%d - %s", pex.getFile(), pex.getLine(),
                   pex.getError());
    return false;
  }

  Setting& root = cfg.getRoot();

  /**
   * Iterate over sections. Best thing to do here would be to have other
   * components of the program registering a callback here, to parse their
   * section of the configuration file.
   */
  for (auto section = root.begin(); section != root.end(); section++) {
    std::string name = section->getName();
    std::error_code ec;
    TRANSPORT_LOGD("Parsing Section: %s", name.c_str());

    auto it = configuration_parsers_.find(name);
    if (it != configuration_parsers_.end() && !it->second.first) {
      TRANSPORT_LOGD("Found valid configuration parser");
      it->second.second(*section, ec);
      it->second.first = true;
    }
  }

  return true;
}

void GlobalConfiguration::parseConfiguration(const std::string& path) {
  // Check if an environment variable with the configuration path exists. COnf
  // variable comes first.
  std::unique_lock<std::mutex> lck(cp_mtx_);

  if (const char* env_c = std::getenv(GlobalConfiguration::conf_file)) {
    parseTransportConfig(env_c);
  } else if (!path.empty()) {
    conf_file_path_ = path;
    parseTransportConfig(conf_file_path_);
  } else {
    TRANSPORT_LOGD(
        "Called parseConfiguration but no configuration file was provided.");
  }
}

void GlobalConfiguration::registerConfigurationSetter(
    const std::string& key, const SetCallback& set_callback) {
  std::unique_lock<std::mutex> lck(cp_mtx_);
  if (configuration_setters_.find(key) != configuration_setters_.end()) {
    TRANSPORT_LOGW(
        "Trying to register configuration setter %s twice. Ignoring second "
        "registration attempt.",
        key.c_str());
  } else {
    configuration_setters_.emplace(key, set_callback);
  }
}

void GlobalConfiguration::registerConfigurationGetter(
    const std::string& key, const GetCallback& get_callback) {
  std::unique_lock<std::mutex> lck(cp_mtx_);
  if (configuration_getters_.find(key) != configuration_getters_.end()) {
    TRANSPORT_LOGW(
        "Trying to register configuration getter %s twice. Ignoring second "
        "registration attempt.",
        key.c_str());
  } else {
    configuration_getters_.emplace(key, get_callback);
  }
}

void GlobalConfiguration::registerConfigurationParser(
    const std::string& key, const ParserCallback& parser) {
  std::unique_lock<std::mutex> lck(cp_mtx_);
  if (configuration_parsers_.find(key) != configuration_parsers_.end()) {
    TRANSPORT_LOGW(
        "Trying to register configuration key %s twice. Ignoring second "
        "registration attempt.",
        key.c_str());
  } else {
    configuration_parsers_.emplace(key, std::make_pair(false, parser));

    // Trigger a parsing of the configuration.
    if (!conf_file_path_.empty()) {
      parseTransportConfig(conf_file_path_);
    }
  }
}

void GlobalConfiguration::unregisterConfigurationParser(
    const std::string& key) {
  std::unique_lock<std::mutex> lck(cp_mtx_);
  auto it = configuration_parsers_.find(key);
  if (it != configuration_parsers_.end()) {
    configuration_parsers_.erase(it);
  }
}

void GlobalConfiguration::unregisterConfigurationSetter(
    const std::string& key) {
  std::unique_lock<std::mutex> lck(cp_mtx_);
  auto it = configuration_setters_.find(key);
  if (it != configuration_setters_.end()) {
    configuration_setters_.erase(it);
  }
}

void GlobalConfiguration::unregisterConfigurationGetter(
    const std::string& key) {
  std::unique_lock<std::mutex> lck(cp_mtx_);
  auto it = configuration_getters_.find(key);
  if (it != configuration_getters_.end()) {
    configuration_getters_.erase(it);
  }
}

void GlobalConfiguration::getConfiguration(
    interface::global_config::ConfigurationObject& configuration_object,
    std::error_code& ec) {
  auto it = configuration_getters_.find(configuration_object.getKey());

  if (it != configuration_getters_.end()) {
    it->second(configuration_object, ec);
  }
}

void GlobalConfiguration::setConfiguration(
    const interface::global_config::ConfigurationObject& configuration_object,
    std::error_code& ec) {
  auto it = configuration_setters_.find(configuration_object.getKey());

  if (it != configuration_setters_.end()) {
    it->second(configuration_object, ec);
  }
}

}  // namespace core
}  // namespace transport