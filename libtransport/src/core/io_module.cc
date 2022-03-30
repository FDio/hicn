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
  void *handle = 0;
  IoModule *module = 0;
  IoModule *(*creator)(void) = 0;
  const char *error = 0;

  // open module
  handle = dlopen(module_name, RTLD_NOW);
  if (!handle) {
    if ((error = dlerror()) != 0) {
      LOG(ERROR) << error;
    }
    return 0;
  }

  // get factory method
  creator = (IoModule * (*)(void)) dlsym(handle, "create_module");
  if (!creator) {
    if ((error = dlerror()) != 0) {
      LOG(ERROR) << error;
    }

    return 0;
  }

  // create object and return it
  module = (*creator)();
  module->handle_ = handle;

  return module;
#endif
}

bool IoModule::unload(IoModule *module) {
  if (!module) {
    return false;
  }

#ifdef ANDROID
  delete module;
#else
  // destroy object and close module
  void *handle = module->handle_;
  delete module;
  dlclose(handle);
#endif

  return true;
}

}  // namespace core
}  // namespace transport
