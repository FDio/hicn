/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Copyright 2017 Facebook, Inc.
 *
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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

namespace utils {

namespace hash {

/*
 * Fowler / Noll / Vo (FNV) Hash
 *     http://www.isthe.com/chongo/tech/comp/fnv/
 */

const uint32_t FNV_32_HASH_START = 2166136261UL;
const uint64_t FNV_64_HASH_START = 14695981039346656037ULL;

TRANSPORT_ALWAYS_INLINE uint32_t fnv32(const char *s,
                                       uint32_t hash = FNV_32_HASH_START) {
  for (; *s; ++s) {
    hash +=
        (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    hash ^= *s;
  }
  return hash;
}

TRANSPORT_ALWAYS_INLINE uint32_t fnv32_buf(const void *buf, size_t n,
                                           uint32_t hash = FNV_32_HASH_START) {
  // forcing signed char, since other platforms can use unsigned
  const signed char *char_buf = reinterpret_cast<const signed char *>(buf);

  for (size_t i = 0; i < n; ++i) {
    hash +=
        (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    hash ^= char_buf[i];
  }

  return hash;
}

TRANSPORT_ALWAYS_INLINE uint32_t fnv32(const std::string &str,
                                       uint32_t hash = FNV_32_HASH_START) {
  return fnv32_buf(str.data(), str.size(), hash);
}

TRANSPORT_ALWAYS_INLINE uint64_t fnv64(const char *s,
                                       uint64_t hash = FNV_64_HASH_START) {
  for (; *s; ++s) {
    hash += (hash << 1) + (hash << 4) + (hash << 5) + (hash << 7) +
            (hash << 8) + (hash << 40);
    hash ^= *s;
  }
  return hash;
}

TRANSPORT_ALWAYS_INLINE uint64_t fnv64_buf(const void *buf, size_t n,
                                           uint64_t hash = FNV_64_HASH_START) {
  // forcing signed char, since other platforms can use unsigned
  const signed char *char_buf = reinterpret_cast<const signed char *>(buf);

  for (size_t i = 0; i < n; ++i) {
    hash += (hash << 1) + (hash << 4) + (hash << 5) + (hash << 7) +
            (hash << 8) + (hash << 40);
    hash ^= char_buf[i];
  }
  return hash;
}

TRANSPORT_ALWAYS_INLINE uint64_t fnv64(const std::string &str,
                                       uint64_t hash = FNV_64_HASH_START) {
  return fnv64_buf(str.data(), str.size(), hash);
}

}  // namespace hash

}  // namespace utils
