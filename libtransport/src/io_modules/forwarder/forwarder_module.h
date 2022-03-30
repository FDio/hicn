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
#include <io_modules/forwarder/forwarder.h>

#include <atomic>

namespace transport {

namespace core {

class Forwarder;

class ForwarderModule : public IoModule {
  static constexpr std::uint16_t interface_mtu = 1500;

 public:
  ForwarderModule();

  ~ForwarderModule();

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

  std::uint32_t getMtu() override;

  bool isControlMessage(utils::MemBuf &packet_buffer) override;

  void processControlMessageReply(utils::MemBuf &packet_buffer) override;

  void closeConnection() override;

 private:
  static void initForwarder();

 private:
  std::string name_;
  Connector::Id connector_id_;
  std::shared_ptr<Forwarder> forwarder_ptr_;
  Forwarder &forwarder_;
};

extern "C" IoModule *create_module(void);

}  // namespace core

}  // namespace transport
