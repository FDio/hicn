/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <hicn/transport/core/prefix.h>
#include <hicn/transport/utils/hash.h>

#include <sstream>
#include <string>

#pragma once

TRANSPORT_ALWAYS_INLINE std::string generatePrefix(
    const std::string& prefix_url, const std::string& first_ipv6_word) {
  const char* str = prefix_url.c_str();
  uint16_t pos = 0;

  if (strncmp("http://", str, 7) == 0) {
    pos = 7;
  } else if (strncmp("https://", str, 8) == 0) {
    pos = 8;
  }

  str += pos;

  uint32_t locator_hash = utils::hash::fnv32_buf(str, strlen(str));

  std::stringstream stream;
  stream << first_ipv6_word << ":0";

  for (uint16_t* word = (uint16_t*)&locator_hash;
       std::size_t(word) < (std::size_t(&locator_hash) + sizeof(locator_hash));
       word++) {
    stream << ":" << std::hex << *word;
  }

  stream << "::";

  return stream.str();
}