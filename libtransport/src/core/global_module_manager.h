/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <glog/logging.h>
#include <hicn/transport/utils/singleton.h>

#ifndef _WIN32
#include <dlfcn.h>
#endif

#include <atomic>
#include <iostream>
#include <mutex>
#include <unordered_map>

namespace transport {
namespace core {

class GlobalModuleManager : public utils::Singleton<GlobalModuleManager> {
 public:
  friend class utils::Singleton<GlobalModuleManager>;

  ~GlobalModuleManager() {
    for (const auto &[key, value] : modules_) {
      unload(value);
    }
  }

  void *loadModule(const std::string &module_name) {
    void *handle = nullptr;
    const char *error = nullptr;

    // Lock
    std::unique_lock lck(mtx_);

    auto it = modules_.find(module_name);
    if (it != modules_.end()) {
      return it->second;
    }

    // open module
    handle = dlopen(module_name.c_str(), RTLD_NOW);
    if (!handle) {
      if ((error = dlerror()) != nullptr) {
        LOG(ERROR) << error;
      }
      return nullptr;
    }

    auto ret = modules_.try_emplace(module_name, handle);
    DCHECK(ret.second);

    return handle;
  }

  void unload(void *handle) {
    // destroy object and close module
    dlclose(handle);
  }

  bool unloadModule(const std::string &module_name) {
    // Lock
    std::unique_lock lck(mtx_);
    auto it = modules_.find(module_name);
    if (it != modules_.end()) {
      unload(it->second);
      return true;
    }

    return false;
  }

 private:
  GlobalModuleManager() = default;
  std::mutex mtx_;
  std::unordered_map<std::string, void *> modules_;
};

}  // namespace core
}  // namespace transport