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

#include <string>
#include <vector>

/**
 * Global configuration interface.
 */

namespace transport {
namespace interface {
namespace global_config {

class GlobalConfigInterface {
 public:
  GlobalConfigInterface();
  ~GlobalConfigInterface();
  void parseConfigurationFile(const std::string& path = "") const;

 private:
  void libtransportConfigInit() const;
  void libtransportConfigTerminate() const;
};

class ConfigurationObject {
 public:
  /**
   * Set configuration.
   */
  void set();

  /**
   * Get configuration.
   */
  void get();

  /**
   * Get configuration key
   */
  virtual std::string getKey() const = 0;
};

class IoModuleConfiguration : public ConfigurationObject {
 public:
  static inline char section[] = "io_module";

  std::string getKey() const override { return section; }

  std::string name;
  std::vector<std::string> search_path;
};

}  // namespace global_config
}  // namespace interface
}  // namespace transport