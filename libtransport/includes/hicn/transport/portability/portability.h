/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Copyright 2017 Facebook, Inc.
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

#ifdef _WIN32
#include <hicn/transport/portability/win_portability.h>
#endif

#include <hicn/transport/portability/c_portability.h>

#include <string.h>
#include <cstddef>

namespace portability {

constexpr bool little_endian_arch = __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__;
constexpr bool big_endian_arch = !little_endian_arch;

#if defined(__GNUC__)
#define _TRANSPORT_GNU_DISABLE_WARNING(warning) #warning
#define TRANSPORT_GNU_DISABLE_WARNING(warning) \
  _Pragma(_TRANSPORT_GNU_DISABLE_WARNING(GCC diagnostic ignored warning))

#ifdef __clang__
#define TRANSPORT_CLANG_DISABLE_WARNING(warning) \
  TRANSPORT_GNU_DISABLE_WARNING(warning)
#define TRANSPORT_GCC_DISABLE_WARNING(warning)
#else
#define TRANSPORT_CLANG_DISABLE_WARNING(warning)
#define TRANSPORT_GCC_DISABLE_WARNING(warning) \
  TRANSPORT_GNU_DISABLE_WARNING(warning)
#endif
#endif

}  // namespace portability
