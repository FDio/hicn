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
#include <core/local_connector.h>
#include <io_modules/forwarder/forwarder.h>
#include <io_modules/forwarder/global_id_counter.h>
#include <io_modules/forwarder/udp_tunnel.h>
#include <io_modules/forwarder/udp_tunnel_listener.h>

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
    Connector::OnReconnectCallback &&reconnect_callback) {
  utils::SpinLock::Acquire locked(connector_lock_);
  auto id = GlobalCounter<Connector::Id>::getInstance().getNext();
  auto connector = std::make_shared<LocalConnector>(
      io_service, receive_callback, nullptr, nullptr, reconnect_callback);
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

void Forwarder::onPacketFromListener(Connector *connector,
                                     utils::MemBuf &packet_buffer,
                                     const std::error_code &ec) {
  // Create connector
  connector->setReceiveCallback(
      std::bind(&Forwarder::onPacketReceived, this, std::placeholders::_1,
                std::placeholders::_2, std::placeholders::_3));

  TRANSPORT_LOGD("Packet received from listener.");

  {
    utils::SpinLock::Acquire locked(connector_lock_);
    remote_connectors_.emplace(connector->getConnectorId(),
                               connector->shared_from_this());
  }
  // TODO Check if control packet or not. For the moment it is not.
  onPacketReceived(connector, packet_buffer, ec);
}

void Forwarder::onPacketReceived(Connector *connector,
                                 utils::MemBuf &packet_buffer,
                                 const std::error_code &ec) {
  // Figure out the type of packet we received
  bool is_interest = Packet::isInterest(packet_buffer.data());

  Packet *packet = nullptr;
  if (is_interest) {
    packet = static_cast<Interest *>(&packet_buffer);
  } else {
    packet = static_cast<ContentObject *>(&packet_buffer);
  }

  for (auto &c : local_connectors_) {
    auto role = c.second->getRole();
    auto is_producer = role == Connector::Role::PRODUCER;
    if ((is_producer && is_interest) || (!is_producer && !is_interest)) {
      c.second->send(*packet);
    } else {
      TRANSPORT_LOGD(
          "Error sending packet to local connector. is_interest = %d - "
          "is_producer = %d",
          (int)is_interest, (int)is_producer);
    }
  }

  // PCS Lookup + FIB lookup. Skip for now

  // Forward packet to local connectors
}

void Forwarder::send(Packet &packet) {
  // TODo Here a nice PIT/CS / FIB would be required:)
  // For now let's just forward the packet on the remote connector we get
  if (remote_connectors_.begin() == remote_connectors_.end()) {
    return;
  }

  auto remote_endpoint =
      remote_connectors_.begin()->second->getRemoteEndpoint();
  TRANSPORT_LOGD("Sending packet to: %s:%u",
                 remote_endpoint.getAddress().to_string().c_str(),
                 remote_endpoint.getPort());
  remote_connectors_.begin()->second->send(packet);
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
    TRANSPORT_LOGD("Forwarder threads from config file: %u", n_threads);
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

      TRANSPORT_LOGD("Adding listener %s, (%s:%u)", list.name.c_str(),
                     list.address.c_str(), list.port);
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

      TRANSPORT_LOGD("Adding connector %s, (%s:%u %s:%u)", conn.name.c_str(),
                     conn.local_address.c_str(), conn.local_port,
                     conn.remote_address.c_str(), conn.remote_port);
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

      TRANSPORT_LOGD("Adding route %s %s (%s %u)", r.name.c_str(),
                     r.prefix.c_str(), r.connector.c_str(), r.weight);
      config_.addRoute(std::move(r));
    }
  }
}

}  // namespace core
}  // namespace transport