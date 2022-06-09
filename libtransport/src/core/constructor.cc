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

#include <core/global_configuration.h>
#include <core/global_module_manager.h>
#include <core/global_workers.h>
#include <hicn/transport/core/global_object_pool.h>

namespace transport {
namespace core {

void __attribute__((constructor)) libtransportInit() {
  // First the global module manager is initialized
  GlobalModuleManager::getInstance();
  // Then the packet allocator is initialized
  PacketManager<>::getInstance();
  // Then the global configuration is initialized
  GlobalConfiguration::getInstance();
  // Then the global workers are initialized
  GlobalWorkers::getInstance();
}

}  // namespace core
}  // namespace transport