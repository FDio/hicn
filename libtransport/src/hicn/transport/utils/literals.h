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

#include <cstdint>

TRANSPORT_ALWAYS_INLINE std::uint8_t operator"" _U8(unsigned long long value) {
  return static_cast<std::uint8_t>(value);
}

TRANSPORT_ALWAYS_INLINE std::uint16_t operator"" _U16(
    unsigned long long value) {
  return static_cast<std::uint16_t>(value);
}

TRANSPORT_ALWAYS_INLINE std::uint32_t operator"" _U32(
    unsigned long long value) {
  return static_cast<std::uint32_t>(value);
}

TRANSPORT_ALWAYS_INLINE std::uint64_t operator"" _U64(
    unsigned long long value) {
  return static_cast<std::uint64_t>(value);
}

TRANSPORT_ALWAYS_INLINE std::int8_t operator"" _I8(unsigned long long value) {
  return static_cast<std::int8_t>(value);
}

TRANSPORT_ALWAYS_INLINE std::int16_t operator"" _I16(unsigned long long value) {
  return static_cast<std::int16_t>(value);
}

TRANSPORT_ALWAYS_INLINE std::int32_t operator"" _I32(unsigned long long value) {
  return static_cast<std::int32_t>(value);
}

TRANSPORT_ALWAYS_INLINE std::int64_t operator"" _I64(unsigned long long value) {
  return static_cast<std::int64_t>(value);
}