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

#include <core/forwarder_interface.h>
#include <core/hicn_forwarder_interface.h>
#include <core/manifest_format_fixed.h>
#include <core/manifest_inline.h>
#include <core/portal.h>

#ifdef __linux__
#ifndef __ANDROID__
#include <hicn/transport/core/raw_socket_interface.h>
#ifdef __vpp__
#include <hicn/transport/core/vpp_forwarder_interface.h>
#endif
#endif
#endif

namespace transport {

namespace core {

using HicnForwarderPortal = Portal<HicnForwarderInterface>;

#ifdef __linux__
#ifndef __ANDROID__
using RawSocketPortal = Portal<RawSocketInterface>;
#endif
#ifdef __vpp__
using VPPForwarderPortal = Portal<VPPForwarderInterface>;
#endif
#endif

using ContentObjectManifest = core::ManifestInline<ContentObject, Fixed>;
using InterestManifest = core::ManifestInline<Interest, Fixed>;

}  // namespace core

}  // namespace transport
