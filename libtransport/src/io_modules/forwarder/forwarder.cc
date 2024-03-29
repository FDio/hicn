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

#include <core/global_configuration.h>
#include <core/global_id_counter.h>
#include <core/local_connector.h>
#include <core/udp_connector.h>
#include <core/udp_listener.h>
#include <glog/logging.h>
#include <io_modules/forwarder/forwarder.h>

namespace transport {

namespace core {

constexpr char Forwarder::forwarder_config_section[];

Forwarder::Forwarder() : config_() {
  using namespace std::placeholders;
  GlobalConfiguration::getInstance().registerConfigurationParser(
      forwarder_config_section,
      std::bind(&Forwarder::parseForwarderConfiguration, this, _1, _2));

  if (!config_.empty()) {
    initThreads();
    initListeners();
    initConnectors();
  }
}

Forwarder::~Forwarder() {
  for (auto &l : listeners_) {
    l->close();
  }

  for (auto &c : remote_connectors_) {
    c.second->close();
  }

  GlobalConfiguration::getInstance().unregisterConfigurationParser(
      forwarder_config_section);
}

void Forwarder::initThreads() {
  for (unsigned i = 0; i < config_.getThreadNumber(); i++) {
    thread_pool_.emplace_back(io_service_, /* detached */ false);
  }
}

void Forwarder::initListeners() {
  using namespace std::placeholders;
  for (auto &l : config_.getListeners()) {
    listeners_.emplace_back(std::make_shared<UdpTunnelListener>(
        io_service_,
        std::bind(&Forwarder::onPacketFromListener, this, _1, _2, _3),
        asio::ip::udp::endpoint(asio::ip::address::from_string(l.address),
                                l.port)));
  }
}

void Forwarder::initConnectors() {
  using namespace std::placeholders;
  for (auto &c : config_.getConnectors()) {
    auto id = GlobalCounter<Connector::Id>::getInstance().getNext();
    auto conn = new UdpTunnelConnector(
        io_service_, std::bind(&Forwarder::onPacketReceived, this, _1, _2, _3),
        std::bind(&Forwarder::onPacketSent, this, _1, _2),
        std::bind(&Forwarder::onConnectorClosed, this, _1),
        std::bind(&Forwarder::onConnectorReconnected, this, _1));
    conn->setConnectorId(id);
    remote_connectors_.emplace(id, conn);
    conn->connect(c.remote_address, c.remote_port, c.local_address,
                  c.local_port);
  }
}

Connector::Id Forwarder::registerLocalConnector(
    asio::io_service &io_service,
    Connector::PacketReceivedCallback &&receive_callback,
    Connector::PacketSentCallback &&sent_callback,
    Connector::OnCloseCallback &&close_callback,
    Connector::OnReconnectCallback &&reconnect_callback) {
  utils::SpinLock::Acquire locked(connector_lock_);
  auto id = GlobalCounter<Connector::Id>::getInstance().getNext();
  auto connector = std::make_shared<LocalConnector>(
      io_service, std::move(receive_callback), std::move(sent_callback),
      std::move(close_callback), std::move(reconnect_callback));
  connector->setConnectorId(id);
  local_connectors_.emplace(id, std::move(connector));
  return id;
}

Forwarder &Forwarder::deleteConnector(Connector::Id id) {
  utils::SpinLock::Acquire locked(connector_lock_);
  auto it = local_connectors_.find(id);
  if (it != local_connectors_.end()) {
    it->second->close();
    local_connectors_.erase(it);
  } else {
  }

  return *this;
}

Connector::Ptr Forwarder::getConnector(Connector::Id id) {
  utils::SpinLock::Acquire locked(connector_lock_);
  auto it = local_connectors_.find(id);
  if (it != local_connectors_.end()) {
    return it->second;
  }

  return nullptr;
}

void Forwarder::onPacketFromListener(
    Connector *connector, const std::vector<utils::MemBuf::Ptr> &packets,
    const std::error_code &ec) {
  // Create connector
  connector->setReceiveCallback(
      std::bind(&Forwarder::onPacketReceived, this, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3));

  DLOG_IF(INFO, VLOG_IS_ON(3)) << "Packet received from listener.";

  {
    utils::SpinLock::Acquire locked(connector_lock_);
    remote_connectors_.emplace(connector->getConnectorId(),
                               connector->shared_from_this());
  }

  // TODO Check if control packet or not. For the moment it is not.
  onPacketReceived(connector, packets, ec);
}

void Forwarder::onPacketReceived(Connector *connector,
                                 const std::vector<utils::MemBuf::Ptr> &packets,
                                 const std::error_code &ec) {
  if (ec) {
    LOG(ERROR) << "Error receiving packet: " << ec.message();
    return;
  }

  for (auto &c : local_connectors_) {
    c.second->receive(packets);
  }

  // PCS Lookup + FIB lookup. Skip for now

  // Forward packet to local connectors
}

void Forwarder::send(Packet &packet, Connector::Id connector_id) {
  // TODo Here a nice PIT/CS / FIB would be required:)
  // For now let's just forward the packet on the remote connector we get
  for (auto &c : remote_connectors_) {
    auto remote_endpoint = c.second->getRemoteEndpoint();
    DLOG_IF(INFO, VLOG_IS_ON(3))
        << "Sending packet to: " << remote_endpoint.getAddress() << ":"
        << remote_endpoint.getPort();
    c.second->send(packet);
  }

  for (auto &c : local_connectors_) {
    if (c.first != connector_id) {
      DLOG_IF(INFO, VLOG_IS_ON(3))
          << "Sending packet to local connector " << c.first << std::endl;
      c.second->receive({packet.shared_from_this()});
    }
  }
}

void Forwarder::onPacketSent(Connector *connector, const std::error_code &ec) {}

void Forwarder::onConnectorClosed(Connector *connector) {}

void Forwarder::onConnectorReconnected(Connector *connector) {}

void Forwarder::parseForwarderConfiguration(
    const libconfig::Setting &forwarder_config, std::error_code &ec) {
  using namespace libconfig;

  // n_thread
  if (forwarder_config.exists("n_threads")) {
    // Get number of threads
    int n_threads = 1;
    forwarder_config.lookupValue("n_threads", n_threads);
    VLOG(1) << "Forwarder threads from config file: " << n_threads;
    config_.setThreadNumber(n_threads);
  }

  // listeners
  if (forwarder_config.exists("listeners")) {
    // get path where looking for modules
    const Setting &listeners = forwarder_config.lookup("listeners");
    auto count = listeners.getLength();

    for (int i = 0; i < count; i++) {
      const Setting &listener = listeners[i];
      ListenerConfig list;
      unsigned port;

      list.name = listener.getName();
      listener.lookupValue("local_address", list.address);
      listener.lookupValue("local_port", port);
      list.port = (uint16_t)(port);

      VLOG(1) << "Adding listener " << list.name << ", ( " << list.address
              << ":" << list.port << ")";
      config_.addListener(std::move(list));
    }
  }

  // connectors
  if (forwarder_config.exists("connectors")) {
    // get path where looking for modules
    const Setting &connectors = forwarder_config.lookup("connectors");
    auto count = connectors.getLength();

    for (int i = 0; i < count; i++) {
      const Setting &connector = connectors[i];
      ConnectorConfig conn;

      conn.name = connector.getName();
      unsigned port = 0;

      if (!connector.lookupValue("local_address", conn.local_address)) {
        conn.local_address = "";
      }

      if (!connector.lookupValue("local_port", port)) {
        port = 0;
      }

      conn.local_port = (uint16_t)(port);

      if (!connector.lookupValue("remote_address", conn.remote_address)) {
        throw errors::RuntimeException(
            "Error in configuration file: remote_address is a mandatory field "
            "of Connectors.");
      }

      if (!connector.lookupValue("remote_port", port)) {
        throw errors::RuntimeException(
            "Error in configuration file: remote_port is a mandatory field "
            "of Connectors.");
      }

      conn.remote_port = (uint16_t)(port);

      VLOG(1) << "Adding connector " << conn.name << ", (" << conn.local_address
              << ":" << conn.local_port << " " << conn.remote_address << ":"
              << conn.remote_port << ")";
      config_.addConnector(std::move(conn));
    }
  }

  // Routes
  if (forwarder_config.exists("routes")) {
    const Setting &routes = forwarder_config.lookup("routes");
    auto count = routes.getLength();

    for (int i = 0; i < count; i++) {
      const Setting &route = routes[i];
      RouteConfig r;
      unsigned weight;

      r.name = route.getName();
      route.lookupValue("prefix", r.prefix);
      route.lookupValue("weight", weight);
      route.lookupValue("connector", r.connector);
      r.weight = (uint16_t)(weight);

      VLOG(1) << "Adding route " << r.name << " " << r.prefix << " ("
              << r.connector << " " << r.weight << ")";
      config_.addRoute(std::move(r));
    }
  }
}

}  // namespace core
}  // namespace transport
