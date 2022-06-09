/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <hicn/transport/core/asio_wrapper.h>
#include <hicn/transport/core/connector.h>
#include <hicn/transport/core/packet.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/portability/endianess.h>
#include <hicn/transport/portability/portability.h>
#include <hicn/transport/utils/chrono_typedefs.h>
#include <hicn/transport/utils/membuf.h>

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

class Connector;

class IoModule : utils::NonCopyable {
 protected:
  IoModule()
      : inet_address_({}),
        inet6_address_({}),
        mtu_(1500),
        output_interface_(""),
        content_store_reserved_(5000) {
    inet_address_.v4.as_u32 = portability::host_to_net(0x7f00001);
    inet6_address_.v6.as_u8[15] = 0x01;
  }

 public:
  static IoModule *load(const char *);

 public:
  virtual ~IoModule();

  virtual void connect(bool is_consumer = true) = 0;

  virtual bool isConnected() = 0;

  virtual void init(Connector::PacketReceivedCallback &&receive_callback,
                    Connector::PacketSentCallback &&sent_callback,
                    Connector::OnCloseCallback &&close_callback,
                    Connector::OnReconnectCallback &&reconnect_callback,
                    asio::io_service &io_service,
                    const std::string &app_name = "Libtransport") = 0;

  virtual void registerRoute(const Prefix &prefix) = 0;
  virtual void sendMapme() {}

  virtual void setForwardingStrategy(const Prefix &prefix,
                                     std::string &strategy){};

  virtual std::uint32_t getMtu() = 0;

  virtual bool isControlMessage(utils::MemBuf &packet_buffer) = 0;

  virtual void processControlMessageReply(utils::MemBuf &packet_buffer) = 0;

  virtual void closeConnection() = 0;

  virtual void send(Packet &packet) {
    counters_.tx_packets++;
    counters_.tx_bytes += packet.payloadSize() + packet.headerSize();

    if (_is_ipv4(packet.getFormat())) {
      packet.setLocator(inet_address_);
    } else {
      packet.setLocator(inet6_address_);
    }
  }

  virtual void send(const utils::MemBuf::Ptr &buffer) = 0;

  void setContentStoreSize(uint32_t cs_size) {
    content_store_reserved_ = cs_size;
  }

  uint32_t getContentStoreSize() const { return content_store_reserved_; }

  void setOutputInterface(const std::string &interface) {
    output_interface_ = interface;
  }

  const std::string &getOutputInterface() { return output_interface_; }

 protected:
  ip_address_t inet_address_;
  ip_address_t inet6_address_;
  uint16_t mtu_;
  std::string output_interface_;
  uint32_t content_store_reserved_;
  Counters counters_;
};

extern "C" IoModule *createModule();

}  // namespace core
}  // namespace transport
