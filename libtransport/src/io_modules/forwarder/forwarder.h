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

#include <core/udp_listener.h>
#include <hicn/transport/core/io_module.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/utils/event_thread.h>
#include <hicn/transport/utils/singleton.h>
#include <hicn/transport/utils/spinlock.h>
#include <io_modules/forwarder/configuration.h>

#include <atomic>
#include <libconfig.h++>
#include <unordered_map>

namespace transport {

namespace core {

class Forwarder {
  static constexpr char forwarder_config_section[] = "forwarder";

 public:
  Forwarder();

  ~Forwarder();

  void initThreads();
  void initListeners();
  void initConnectors();

  Connector::Id registerLocalConnector(
      asio::io_service &io_service,
      Connector::PacketReceivedCallback &&receive_callback,
      Connector::PacketSentCallback &&sent_callback,
      Connector::OnReconnectCallback &&reconnect_callback);

  Forwarder &deleteConnector(Connector::Id id);

  Connector::Ptr getConnector(Connector::Id id);

  void send(Packet &packet);

  void stop();

 private:
  void onPacketFromListener(Connector *connector,
                            const std::vector<utils::MemBuf::Ptr> &packets,
                            const std::error_code &ec);
  void onPacketReceived(Connector *connector,
                        const std::vector<utils::MemBuf::Ptr> &packets,
                        const std::error_code &ec);
  void onPacketSent(Connector *connector, const std::error_code &ec);
  void onConnectorClosed(Connector *connector);
  void onConnectorReconnected(Connector *connector);

  void parseForwarderConfiguration(const libconfig::Setting &io_config,
                                   std::error_code &ec);

  asio::io_service io_service_;
  utils::SpinLock connector_lock_;

  /**
   * Connectors and listeners must be declares *before* thread_pool_, so that
   * threads destructors will wait for them to gracefully close before being
   * destroyed.
   */
  std::unordered_map<Connector::Id, Connector::Ptr> remote_connectors_;
  std::unordered_map<Connector::Id, Connector::Ptr> local_connectors_;
  std::vector<UdpTunnelListener::Ptr> listeners_;

  std::vector<utils::EventThread> thread_pool_;

  Configuration config_;
};

class ForwarderGlobal : public ::utils::Singleton<ForwarderGlobal> {
  friend class utils::Singleton<ForwarderGlobal>;

 public:
  ~ForwarderGlobal() {}
  std::shared_ptr<Forwarder> &getReference() { return forwarder_; }

 private:
  ForwarderGlobal() : forwarder_(std::make_shared<Forwarder>()) {}

 private:
  std::shared_ptr<Forwarder> forwarder_;
};

}  // namespace core

}  // namespace transport
