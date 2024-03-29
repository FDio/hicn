/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

extern "C" {
#ifndef _WIN32
TRANSPORT_CLANG_DISABLE_WARNING("-Wextern-c-compat")
#endif
#include <hicn/base.h>
};

namespace transport {

namespace core {

enum class PayloadType : uint16_t {
  DATA = HPT_DATA,
  MANIFEST = HPT_MANIFEST,
  UNSPECIFIED = HPT_UNSPEC
};

}  // end namespace core

}  // end namespace transport
