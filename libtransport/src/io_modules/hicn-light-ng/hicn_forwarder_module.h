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

#include <hicn/transport/core/io_module.h>
#include <hicn/transport/core/prefix.h>

extern "C" {
#include <hicn/ctrl/hicn-light-ng.h>
}

namespace transport {

namespace core {

class UdpTunnelConnector;

class HicnForwarderModule : public IoModule {
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
  void send(const utils::MemBuf::Ptr &buffer) override;

  bool isConnected() override;

  void init(Connector::PacketReceivedCallback &&receive_callback,
            Connector::PacketSentCallback &&sent_callback,
            Connector::OnReconnectCallback &&reconnect_callback,
            asio::io_service &io_service,
            const std::string &app_name = "Libtransport") override;

  void registerRoute(const Prefix &prefix) override;

  void sendMapme() override;

  void setForwardingStrategy(const Prefix &prefix,
                             std::string &strategy) override;

  std::uint32_t getMtu() override;

  bool isControlMessage(utils::MemBuf &packet_buffer) override;

  void processControlMessageReply(utils::MemBuf &packet_buffer) override;

  void closeConnection() override;

 private:
  utils::MemBuf::Ptr createCommandRoute(std::unique_ptr<sockaddr> &&addr,
                                        uint8_t prefix_length);
  utils::MemBuf::Ptr createCommandDeleteConnection();
  utils::MemBuf::Ptr createCommandMapmeSendUpdate();
  utils::MemBuf::Ptr createCommandSetForwardingStrategy(
      std::unique_ptr<sockaddr> &&addr, uint32_t prefix_len,
      std::string strategy);

 private:
  std::shared_ptr<UdpTunnelConnector> connector_;

  /* Sequence number used for sending control messages */
  uint32_t seq_;
};

extern "C" IoModule *create_module(void);

}  // namespace core

}  // namespace transport
