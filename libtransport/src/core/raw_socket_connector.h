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
#include <hicn/transport/core/name.h>

#include <core/connector.h>

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <deque>

namespace transport {

namespace core {

using asio::generic::raw_protocol;
using raw_endpoint = asio::generic::basic_endpoint<raw_protocol>;

class RawSocketConnector : public Connector {
 public:
  RawSocketConnector(PacketReceivedCallback &&receive_callback,
                     OnReconnect &&reconnect_callback,
                     asio::io_service &io_service,
                     std::string app_name = "Libtransport");

  ~RawSocketConnector() override;

  void send(const Packet::MemBufPtr &packet) override;

  void send(const uint8_t *packet, std::size_t len,
            const PacketSentCallback &packet_sent = 0) override;

  void close() override;

  void connect(const std::string &interface_name,
               const std::string &mac_address_str);

 private:
  void doConnect();

  void doRecvPacket();

  void doSendPacket();

 private:
  asio::io_service &io_service_;
  raw_protocol::socket socket_;

  struct ether_header ethernet_header_;

  struct sockaddr_ll link_layer_address_;

  asio::steady_timer timer_;

  utils::ObjectPool<utils::MemBuf>::Ptr read_msg_;

  bool data_available_;
  std::string app_name_;
};

}  // end namespace core

}  // end namespace transport
