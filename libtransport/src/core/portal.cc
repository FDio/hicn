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

#include <core/errors.h>
#include <core/global_configuration.h>
#include <core/portal.h>
#include <hicn/transport/interfaces/global_conf_interface.h>
#include <hicn/transport/portability/platform.h>
#include <hicn/transport/utils/file.h>

#include <libconfig.h++>

using namespace transport::interface::global_config;

namespace transport {
namespace core {

#ifdef ANDROID
static const constexpr char default_module[] = "";
#elif defined(MACINTOSH)
static const constexpr char default_module[] = "hicnlight_module.dylib";
#elif defined(LINUX)
static const constexpr char default_module[] = "hicnlight_module.so";
#elif defined(WINDOWS)
static const constexpr char default_module[] = "hicnlight_module.lib";
#endif

IoModuleConfiguration Portal::conf_;
std::string Portal::io_module_path_ = defaultIoModule();

std::string Portal::defaultIoModule() {
  using namespace std::placeholders;
  GlobalConfiguration::getInstance().registerConfigurationParser(
      io_module_section,
      std::bind(&Portal::parseIoModuleConfiguration, _1, _2));
  GlobalConfiguration::getInstance().registerConfigurationGetter(
      io_module_section, std::bind(&Portal::getModuleConfiguration, _1, _2));
  GlobalConfiguration::getInstance().registerConfigurationSetter(
      io_module_section, std::bind(&Portal::setModuleConfiguration, _1, _2));

  // return default
  conf_.name = default_module;
  return default_module;
}

void Portal::getModuleConfiguration(ConfigurationObject& object,
                                    std::error_code& ec) {
  assert(object.getKey() == io_module_section);

  auto conf = dynamic_cast<const IoModuleConfiguration&>(object);
  conf = conf_;
  ec = std::error_code();
}

std::string getIoModulePath(const std::string& name,
                            const std::vector<std::string>& paths,
                            std::error_code& ec) {
#ifdef LINUX
  std::string extension = ".so";
#elif defined(MACINTOSH)
  std::string extension = ".dylib";
#elif defined(WINDOWS)
  std::string extension = ".lib";
#else
#error "Platform not supported.";
#endif

  std::string complete_path = name;

  if (name.empty()) {
    ec = make_error_code(core_error::configuration_parse_failed);
    return "";
  }

  complete_path += extension;

  for (auto& p : paths) {
    if (p.at(0) != '/') {
      LOG(WARNING) << "Path " << p << " is not an absolute path. Ignoring it.";
      continue;
    }

    if (utils::File::exists(p + "/" + complete_path)) {
      complete_path = p + "/" + complete_path;
      break;
    }
  }

  return complete_path;
}

void Portal::setModuleConfiguration(const ConfigurationObject& object,
                                    std::error_code& ec) {
  assert(object.getKey() == io_module_section);

  const IoModuleConfiguration& conf =
      dynamic_cast<const IoModuleConfiguration&>(object);
  auto path = getIoModulePath(conf.name, conf.search_path, ec);
  if (!ec) {
    conf_ = conf;
    io_module_path_ = path;
  }
}

void Portal::parseIoModuleConfiguration(const libconfig::Setting& io_config,
                                        std::error_code& ec) {
  using namespace libconfig;
  // path property: the list of paths where to look for the module.
  std::vector<std::string> paths;
  std::string name;

  if (io_config.exists("path")) {
    // get path where looking for modules
    const Setting& path_list = io_config.lookup("path");
    auto count = path_list.getLength();

    for (int i = 0; i < count; i++) {
      paths.emplace_back(path_list[i].c_str());
    }
  }

  if (io_config.exists("name")) {
    io_config.lookupValue("name", name);
  } else {
    ec = make_error_code(core_error::configuration_parse_failed);
    return;
  }

  auto path = getIoModulePath(name, paths, ec);
  if (!ec) {
    conf_.name = name;
    conf_.search_path = paths;
    io_module_path_ = path;
  }
}

}  // namespace core
}  // namespace transport