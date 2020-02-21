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

#include <core/udp_socket_connector.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/chrono_typedefs.h>

#include <deque>

namespace transport {

namespace core {

typedef struct {
  uint64_t rx_packets;
  uint64_t tx_packets;
  uint64_t rx_bytes;
  uint64_t tx_bytes;
  uint64_t rx_errors;
  uint64_t tx_errors;
} Counters;

template <typename Implementation, typename ConnectorType>
class ForwarderInterface {
  static_assert(std::is_base_of<Connector, ConnectorType>::value,
                "T must inherit from connector!");

  static constexpr uint32_t standard_cs_reserved = 5000;

 protected:
  ForwarderInterface(ConnectorType &c)
      : connector_(c),
        inet_address_({}),
        inet6_address_({}),
        mtu_(1500),
        output_interface_(""),
        content_store_reserved_(standard_cs_reserved) {}

 public:
  virtual ~ForwarderInterface() {}

  TRANSPORT_ALWAYS_INLINE void connect(bool is_consumer = true) {
    static_cast<Implementation &>(*this).connect(is_consumer);
  }

  TRANSPORT_ALWAYS_INLINE void registerRoute(Prefix &prefix) {
    static_cast<Implementation &>(*this).registerRoute();
  }

  TRANSPORT_ALWAYS_INLINE std::uint32_t getMtu() {
    return static_cast<Implementation &>(*this).getMtu();
  }

  TRANSPORT_ALWAYS_INLINE static bool isControlMessage(const uint8_t *message) {
    return Implementation::isControlMessageImpl(message);
  }

  template <typename R>
  TRANSPORT_ALWAYS_INLINE void processControlMessageReply(R &&packet_buffer) {
    return static_cast<Implementation &>(*this).processControlMessageReplyImpl(
        std::forward<R &&>(packet_buffer));
  }

  TRANSPORT_ALWAYS_INLINE void closeConnection() {
    return static_cast<Implementation &>(*this).closeConnection();
  }

  template <
      typename R,
      typename = std::enable_if_t<
          std::is_base_of<Packet, typename std::remove_reference_t<R>>::value,
          R>>
  TRANSPORT_ALWAYS_INLINE void send(R &&packet) {
    counters_.tx_packets++;
    counters_.tx_bytes += packet.payloadSize() + packet.headerSize();

    if (_is_ipv4(packet.getFormat())) {
      packet.setLocator(inet_address_);
    } else {
      packet.setLocator(inet6_address_);
    }

    // TRANSPORT_LOGI("Sending packet %s at %lu",
    // packet.getName().toString().c_str(),
    // utils::SteadyClock::now().time_since_epoch().count());
    packet.setChecksum();
    connector_.send(packet.acquireMemBufReference());
  }

  TRANSPORT_ALWAYS_INLINE void send(const uint8_t *packet, std::size_t len) {
    // ASIO_COMPLETION_HANDLER_CHECK(Handler, packet_sent) type_check;
    counters_.tx_packets++;
    counters_.tx_bytes += len;

    // Perfect forwarding
    connector_.send(packet, len);
  }

  TRANSPORT_ALWAYS_INLINE void shutdown() { connector_.close(); }

  TRANSPORT_ALWAYS_INLINE Connector &getConnector() { return connector_; }

  TRANSPORT_ALWAYS_INLINE void setContentStoreSize(uint32_t cs_size) {
    content_store_reserved_ = cs_size;
  }

  TRANSPORT_ALWAYS_INLINE uint32_t getContentStoreSize() const {
    return content_store_reserved_;
  }

  TRANSPORT_ALWAYS_INLINE void setOutputInterface(
      const std::string &interface) {
    output_interface_ = interface;
  }

  TRANSPORT_ALWAYS_INLINE std::string &getOutputInterface() {
    return output_interface_;
  }

 protected:
  ConnectorType &connector_;
  ip_address_t inet_address_;
  ip_address_t inet6_address_;
  uint16_t mtu_;
  std::string output_interface_;
  uint32_t content_store_reserved_;
  Counters counters_;
};

}  // namespace core

}  // namespace transport
