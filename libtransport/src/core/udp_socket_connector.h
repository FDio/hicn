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
#include <hicn/transport/utils/branch_prediction.h>

#include <core/connector.h>

#include <asio.hpp>
#include <asio/steady_timer.hpp>
#include <deque>

namespace transport {
namespace core {

using asio::ip::udp;

class UdpSocketConnector : public Connector {
 public:
  UdpSocketConnector(PacketReceivedCallback &&receive_callback,
                     OnReconnect &&reconnect_callback,
                     asio::io_service &io_service,
                     std::string app_name = "Libtransport");

  ~UdpSocketConnector() override;

  void send(const Packet::MemBufPtr &packet) override;

  void send(const uint8_t *packet, std::size_t len,
            const PacketSentCallback &packet_sent = 0) override;

  void close() override;

  void connect(std::string ip_address = "127.0.0.1", std::string port = "9695");

 private:
  void doConnect();

  void doRead();

  void doWrite();

  void doClose();

  bool checkConnected();

 private:
  void handleDeadline(const std::error_code &ec);

  void startConnectionTimer();

  void tryReconnect();

  asio::io_service &io_service_;
  asio::ip::udp::socket socket_;
  asio::ip::udp::resolver resolver_;
  asio::ip::udp::resolver::iterator endpoint_iterator_;
  asio::steady_timer connection_timer_;

  utils::ObjectPool<utils::MemBuf>::Ptr read_msg_;

  bool is_reconnection_;
  bool data_available_;

  std::string app_name_;
};

}  // end namespace core

}  // end namespace transport
