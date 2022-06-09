/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <hicn/transport/errors/errors.h>

namespace transport {
namespace portability {

#if (__BYTE_ORDER__) == (__ORDER_LITTLE_ENDIAN__)
static constexpr const bool kIsBigEndian = false;
static constexpr const bool kIsLittleEndian = true;
#else
static constexpr const bool kIsBigEndian = true;
static constexpr const bool kIsLittleEndian = false;
#endif

template <typename T>
inline T bswap(T value) {
  throw errors::RuntimeException("Not implemented");
}

template <>
inline int16_t bswap(int16_t value) {
  return __builtin_bswap16(value);
}

template <>
inline int32_t bswap(int32_t value) {
  return __builtin_bswap32(value);
}

template <>
inline int64_t bswap(int64_t value) {
  return __builtin_bswap64(value);
}

template <>
inline uint16_t bswap(uint16_t value) {
  return __builtin_bswap16(value);
}

template <>
inline uint32_t bswap(uint32_t value) {
  return __builtin_bswap32(value);
}

template <>
inline uint64_t bswap(uint64_t value) {
  return __builtin_bswap64(value);
}

template <typename T>
inline T host_to_net(T value) {
  if constexpr (kIsLittleEndian) {
    return bswap(value);
  }

  return value;
}

template <typename T>
inline T net_to_host(T value) {
  if constexpr (kIsLittleEndian) {
    return bswap(value);
  }

  return value;
}

}  // namespace portability
}  // namespace transport