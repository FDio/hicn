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

#include <hicn/transport/core/forwarder_interface.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/core/socket_connector.h>

#include <deque>

namespace transport {

namespace core {

class HicnForwarderInterface
    : public ForwarderInterface<HicnForwarderInterface, SocketConnector> {
 public:
  union addressLight {
    uint32_t ipv4;
    struct in6_addr ipv6;
  };

  struct route_to_self_command {
    uint8_t messageType;
    uint8_t commandID;
    uint16_t length;
    uint32_t seqNum;
    char symbolicOrConnid[16];
    union addressLight address;
    uint16_t cost;
    uint8_t addressType;
    uint8_t len;
  };

  using route_to_self_command = struct route_to_self_command;
  using ConnectorType = SocketConnector;

  HicnForwarderInterface(SocketConnector &connector);

  ~HicnForwarderInterface();

  void connect(bool is_consumer);

  void registerRoute(Prefix &prefix);

  std::uint16_t getMtu() { return interface_mtu; }

 private:
  static constexpr std::uint16_t interface_mtu = 1500;
};

}  // namespace core

}  // namespace transport
