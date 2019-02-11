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
#include <hicn/transport/core/raw_socket_connector.h>

#include <atomic>
#include <deque>

namespace transport {

namespace core {

class RawSocketInterface
    : public ForwarderInterface<RawSocketInterface, RawSocketConnector> {
 public:
  typedef RawSocketConnector ConnectorType;

  RawSocketInterface(RawSocketConnector &connector);

  ~RawSocketInterface();

  void connect(bool is_consumer);

  void registerRoute(Prefix &prefix);

  std::uint16_t getMtu() { return interface_mtu; }

  TRANSPORT_ALWAYS_INLINE static bool isControlMessageImpl(
      const uint8_t *message) {
    return false;
  }

  TRANSPORT_ALWAYS_INLINE void processControlMessageReplyImpl(
      Packet::MemBufPtr &&packet_buffer) {}

  TRANSPORT_ALWAYS_INLINE void closeConnection(){};

 private:
  static constexpr std::uint16_t interface_mtu = 1500;
  std::string remote_mac_address_;
};

}  // namespace core

}  // namespace transport
