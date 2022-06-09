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
#include <core/global_workers.h>
#include <glog/logging.h>
#include <hicn/transport/interfaces/global_conf_interface.h>

#include <system_error>

namespace transport {
namespace interface {
namespace global_config {

GlobalConfigInterface::GlobalConfigInterface() { libtransportConfigInit(); }

GlobalConfigInterface::~GlobalConfigInterface() {
  libtransportConfigTerminate();
}

void GlobalConfigInterface::parseConfigurationFile(
    const std::string &path) const {
  core::GlobalConfiguration::getInstance().parseConfiguration(path);
}

void GlobalConfigInterface::libtransportConfigInit() const {
  // nothing to do
}

void GlobalConfigInterface::libtransportConfigTerminate() const {
  // cleanup workers
  auto &workers = core::GlobalWorkers::getInstance().getWorkers();
  for (auto &worker : workers) {
    worker.stop();
  }
}

void ConfigurationObject::get() {
  std::error_code ec;
  core::GlobalConfiguration::getInstance().getConfiguration(*this, ec);

  if (ec) {
    LOG(ERROR) << "Error setting global config: " << ec.message();
  }
}

void ConfigurationObject::set() {
  std::error_code ec;
  core::GlobalConfiguration::getInstance().setConfiguration(*this, ec);

  if (ec) {
    LOG(ERROR) << "Error setting global config: " << ec.message();
  }
}

}  // namespace global_config
}  // namespace interface
}  // namespace transport