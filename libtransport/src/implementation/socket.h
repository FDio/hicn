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

#include <hicn/transport/config.h>
#include <hicn/transport/interfaces/callbacks.h>
#include <hicn/transport/interfaces/socket_options_default_values.h>
#include <hicn/transport/interfaces/socket_options_keys.h>

#include <core/facade.h>

#define SOCKET_OPTION_GET 0
#define SOCKET_OPTION_NOT_GET 1
#define SOCKET_OPTION_SET 2
#define SOCKET_OPTION_NOT_SET 3
#define SOCKET_OPTION_DEFAULT 12345

namespace transport {
namespace implementation {

// Forward Declarations
template <typename PortalType>
class Socket;

// Define the portal and its connector, depending on the compilation options
// passed by the build tool.
using HicnForwarderPortal = core::HicnForwarderPortal;

#ifdef __linux__
#ifndef __ANDROID__
using RawSocketPortal = core::RawSocketPortal;
#endif
#endif

#ifdef __vpp__
using VPPForwarderPortal = core::VPPForwarderPortal;
using BaseSocket = Socket<VPPForwarderPortal>;
using BasePortal = VPPForwarderPortal;
#else
using BaseSocket = Socket<HicnForwarderPortal>;
using BasePortal = HicnForwarderPortal;
#endif

template <typename PortalType>
class Socket {
  static_assert(std::is_same<PortalType, HicnForwarderPortal>::value
#ifdef __linux__
#ifndef __ANDROID__
                    || std::is_same<PortalType, RawSocketPortal>::value
#ifdef __vpp__
                    || std::is_same<PortalType, VPPForwarderPortal>::value
#endif
#endif
                ,
#else
                ,

#endif
                "This class is not allowed as Portal");

 public:
  using Portal = PortalType;

  virtual asio::io_service &getIoService() = 0;

  virtual void connect() = 0;

  virtual bool isRunning() = 0;

 protected:
  virtual ~Socket(){};
};

}  // namespace implementation

}  // namespace transport
