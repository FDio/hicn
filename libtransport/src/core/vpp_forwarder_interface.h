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

#ifdef __vpp__

#include <hicn/transport/core/prefix.h>

#ifdef always_inline
#undef always_inline
#endif
extern "C" {
#include <vapi/vapi_safe.h>
};

#include <core/forwarder_interface.h>
#include <core/memif_connector.h>

#include <deque>

namespace transport {

namespace core {

class VPPForwarderInterface
    : public ForwarderInterface<VPPForwarderInterface, MemifConnector> {
  static constexpr std::uint16_t interface_mtu = 1500;

 public:
  VPPForwarderInterface(MemifConnector &connector);

  typedef MemifConnector ConnectorType;

  ~VPPForwarderInterface();

  void connect(bool is_consumer);

  void registerRoute(Prefix &prefix);

  TRANSPORT_ALWAYS_INLINE std::uint16_t getMtu() { return interface_mtu; }

  TRANSPORT_ALWAYS_INLINE static bool isControlMessageImpl(
      const uint8_t *message) {
    return false;
  }

  TRANSPORT_ALWAYS_INLINE void processControlMessageReplyImpl(
      Packet::MemBufPtr &&packet_buffer) {}

  void closeConnection();

 private:
  uint32_t getMemifConfiguration();

  void consumerConnection();

  void producerConnection();

  uint32_t memif_id_;
  uint32_t sw_if_index_;
  // A consumer socket in vpp has two faces (ipv4 and ipv6)
  uint32_t face_id1_;
  uint32_t face_id2_;
  bool is_consumer_;
  vapi_ctx_t sock_;
  static std::mutex global_lock_;
};

}  // namespace core

}  // namespace transport

#endif
