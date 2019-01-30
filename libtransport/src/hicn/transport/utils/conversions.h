/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include <hicn/transport/portability/portability.h>

#include <stdio.h>
#include <cstdint>
#include <string>

namespace utils {

static TRANSPORT_ALWAYS_INLINE int convertStringToMacAddress(
    const std::string& mac_address, uint8_t* mac_byte_array) {
  const char* mac = mac_address.c_str();

  sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_byte_array[0],
         &mac_byte_array[1], &mac_byte_array[2], &mac_byte_array[3],
         &mac_byte_array[4], &mac_byte_array[5]);

  return 0;
}

}  // namespace utils