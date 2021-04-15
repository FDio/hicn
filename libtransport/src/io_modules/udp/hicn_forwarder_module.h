/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#include <hicn/transport/core/io_module.h>
#include <hicn/transport/core/prefix.h>

namespace transport {

namespace core {

class UdpSocketConnector;

class HicnForwarderModule : public IoModule {
  static constexpr uint8_t ack_code = 0xc2;
  static constexpr uint8_t nack_code = 0xc3;
  static constexpr std::uint16_t interface_mtu = 1500;

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

  HicnForwarderModule();

  ~HicnForwarderModule();

  void connect(bool is_consumer) override;

  void send(Packet &packet) override;
  void send(const uint8_t *packet, std::size_t len) override;

  bool isConnected() override;

  void init(Connector::PacketReceivedCallback &&receive_callback,
            Connector::OnReconnectCallback &&reconnect_callback,
            asio::io_service &io_service,
            const std::string &app_name = "Libtransport") override;

  void registerRoute(const Prefix &prefix) override;

  std::uint32_t getMtu() override;

  bool isControlMessage(const uint8_t *message) override;

  void processControlMessageReply(utils::MemBuf &packet_buffer) override;

  void closeConnection() override;

 private:
  UdpSocketConnector *connector_;
};

extern "C" IoModule *create_module(void);

}  // namespace core

}  // namespace transport
