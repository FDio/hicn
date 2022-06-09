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

#ifndef _WIN32
#include <dlfcn.h>
#endif
#include <core/global_module_manager.h>
#include <glog/logging.h>
#include <hicn/transport/core/io_module.h>

#include <iostream>

#ifdef ANDROID
#include <io_modules/hicn-light-ng/hicn_forwarder_module.h>
#elif _WIN32
#include <hicn/util/windows/windows_utils.h>
#endif

#include <deque>

namespace transport {
namespace core {

IoModule::~IoModule() {}

IoModule *IoModule::load(const char *module_name) {
#ifdef ANDROID
  return new HicnForwarderModule();
#else
  IoModule *iomodule = nullptr;
  IoModule *(*creator)(void) = nullptr;
  const char *error = nullptr;

  auto handle = GlobalModuleManager::getInstance().loadModule(module_name);

  // get factory method
  creator = (IoModule * (*)(void)) dlsym(handle, "create_module");
  if (!creator) {
    if ((error = dlerror()) != nullptr) {
      LOG(ERROR) << error;
    }

    return nullptr;
  }

  // create object and return it
  iomodule = (*creator)();

  return iomodule;
#endif
}

}  // namespace core
}  // namespace transport
