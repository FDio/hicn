/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

// Generalize warning push/pop.
#if defined(__GNUC__) || defined(__clang__)
// Clang & GCC
#define TRANSPORT_PUSH_WARNING _Pragma("GCC diagnostic push")
#define TRANSPORT_POP_WARNING _Pragma("GCC diagnostic pop")
#define TRANSPORT_GNU_DISABLE_WARNING_INTERNAL2(warningName) #warningName
#define TRANSPORT_GNU_DISABLE_WARNING(warningName) \
  _Pragma(TRANSPORT_GNU_DISABLE_WARNING_INTERNAL2( \
      GCC diagnostic ignored warningName))
#ifdef __clang__
#define TRANSPORT_CLANG_DISABLE_WARNING(warningName) \
  TRANSPORT_GNU_DISABLE_WARNING(warningName)
#define TRANSPORT_GCC_DISABLE_WARNING(warningName)
#else
#define TRANSPORT_CLANG_DISABLE_WARNING(warningName)
#define TRANSPORT_GCC_DISABLE_WARNING(warningName) \
  TRANSPORT_GNU_DISABLE_WARNING(warningName)
#endif
#define TRANSPORT_MSVC_DISABLE_WARNING(warningNumber)
#elif defined(_MSC_VER)
#define TRANSPORT_PUSH_WARNING __pragma(warning(push))
#define TRANSPORT_POP_WARNING __pragma(warning(pop))
// Disable the GCC warnings.
#define TRANSPORT_GNU_DISABLE_WARNING(warningName)
#define TRANSPORT_GCC_DISABLE_WARNING(warningName)
#define TRANSPORT_CLANG_DISABLE_WARNING(warningName)
#define TRANSPORT_MSVC_DISABLE_WARNING(warningNumber) \
  __pragma(warning(disable : warningNumber))
#else
#define TRANSPORT_PUSH_WARNING
#define TRANSPORT_POP_WARNING
#define TRANSPORT_GNU_DISABLE_WARNING(warningName)
#define TRANSPORT_GCC_DISABLE_WARNING(warningName)
#define TRANSPORT_CLANG_DISABLE_WARNING(warningName)
#define TRANSPORT_MSVC_DISABLE_WARNING(warningNumber)
#endif

}  // namespace portability
