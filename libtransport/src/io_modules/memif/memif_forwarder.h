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

#include <core/errors.h>
#include <core/global_id_counter.h>
#include <core/local_connector.h>
#include <core/memif_connector.h>
#include <core/udp_listener.h>
#include <hicn/transport/core/endpoint.h>
#include <hicn/transport/core/io_module.h>
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/utils/event_thread.h>
#include <hicn/transport/utils/singleton.h>
#include <hicn/transport/utils/spinlock.h>
#include <io_modules/memif/hicn_vapi.h>
#include <io_modules/memif/memif_vapi.h>
#include <io_modules/memif/vpp_forwarder_module.h>

extern "C" {
#include <hicn/util/ip_address.h>
#include <vapi/vapi_safe.h>
}

#include <atomic>
#include <libconfig.h++>
#include <random>
#include <unordered_map>
#include <utility>

namespace transport {

namespace core {

class MemifForwarder {
  static inline char forwarder_config_section[] = "memif_forwarder";
  static inline std::string const memif_socket_filename = "/run/vpp/memif.sock";
  static inline uint16_t min_port = 1024;
  static inline uint16_t max_port = 65535;

  using LocalEndpoint = std::pair<Connector::Ptr, Connector::ReceptionBuffer>;
  using LocalEnpointTable = std::unordered_map<std::uint16_t, LocalEndpoint>;

  typedef enum { MASTER = 0, SLAVE = 1 } memif_role_t;

 public:
  using Ptr = std::shared_ptr<MemifForwarder>;

  MemifForwarder()
      : memif_connector_(std::make_unique<MemifConnector>(
            std::bind(&MemifForwarder::onPacketReceived, this,
                      std::placeholders::_1, std::placeholders::_2,
                      std::placeholders::_3),
            std::bind(&MemifForwarder::onPacketSent, this,
                      std::placeholders::_1, std::placeholders::_2),
            std::bind(&MemifForwarder::onConnectorClosed, this,
                      std::placeholders::_1),
            std::bind(&MemifForwarder::onConnectorReconnected, this,
                      std::placeholders::_1))),
        memif_id_(~0),
        sw_if_index_(~0),
        sock_(nullptr),
        local_endpoints_table_(),
        rd_(),
        mt_(rd_()),
        dist_(min_port, max_port),
        connection_promise_(std::promise<bool>()),
        connection_future_(connection_promise_.get_future()) {
    initMemifConnection();
  }

  ~MemifForwarder() { stop(); }

  vapi_ctx_t getVapiCtx() { return sock_; }

  bool isConnected() { return memif_connector_->isConnected(); }

  uint32_t getSwIfIndex() { return sw_if_index_; }

  std::pair<Connector::Id, std::uint16_t> registerLocalConnector(
      asio::io_service &io_service,
      Connector::PacketReceivedCallback &&receive_callback,
      Connector::PacketSentCallback &&sent_callback,
      Connector::OnCloseCallback &&close_callback,
      Connector::OnReconnectCallback &&reconnect_callback) {
    utils::SpinLock::Acquire locked(connector_lock_);

    auto port = allocateLocalPort();
    DCHECK(port > min_port && port < max_port);

    auto id = GlobalCounter<Connector::Id>::getInstance().getNext();
    auto connector = std::make_shared<LocalConnector>(
        io_service, std::move(receive_callback), std::move(sent_callback),
        std::move(close_callback), std::move(reconnect_callback));
    connector->setConnectorId(id);
    connector->setLocalEndpoint(core::Endpoint("0.0.0.0", port));
    local_connectors_.emplace(id, connector);
    local_endpoints_table_.emplace(
        port, std::make_pair(connector, Connector::ReceptionBuffer()));

    // Callback if we are already connected
    if (memif_connector_->isConnected()) {
      connector->reconnect();
    }

    return std::make_pair(id, port);
  }

  MemifForwarder &deleteConnector(Connector::Id id) {
    std::uint16_t port;

    utils::SpinLock::Acquire locked(connector_lock_);
    auto it = local_connectors_.find(id);
    if (it != local_connectors_.end()) {
      it->second->close();
      port = it->second->getLocalEndpoint().getPort();
      local_connectors_.erase(it);

      // it2 must exist
      auto it2 = local_endpoints_table_.find(port);
      DCHECK(it2 != local_endpoints_table_.end());
      local_endpoints_table_.erase(it2);
    }

    return *this;
  }

  Connector::Ptr getConnector(Connector::Id id) {
    utils::SpinLock::Acquire locked(connector_lock_);
    auto it = local_connectors_.find(id);
    if (it != local_connectors_.end()) {
      return it->second;
    }

    return nullptr;
  }

  void send(Packet &packet) {
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Sending packet to memif: " << memif_id_;
    memif_connector_->send(packet);
  }

  void send(const utils::MemBuf::Ptr &buffer) {
    DLOG_IF(INFO, VLOG_IS_ON(3)) << "Sending packet to memif: " << memif_id_;
    memif_connector_->send(buffer);
  }

  void stop() {
    if (sw_if_index_ != uint32_t(~0)) {
      int ret = memif_vapi_delete_memif(sock_, sw_if_index_);
      if (ret < 0) {
        LOG(ERROR) << "Error deleting memif with sw idx " << sw_if_index_;
      }
    }

    memif_connector_->close();
  }

 private:
  // Allocate port for local application
  int allocateLocalPort() {
    std::uint16_t limit = max_port - min_port;

    for (int tries = 0; tries < limit; tries++) {
      std::uint16_t port = dist_(mt_);

      auto ret = local_endpoints_table_.find(port);
      if (ret == local_endpoints_table_.end()) {
        return port;
      }
    }

    return -1;
  }

  /**
   * @brief Create a memif interface in the local VPP forwarder.
   */
  uint32_t getMemifConfiguration() {
    memif_create_params_t input_params = {0};

    int ret = memif_vapi_get_next_memif_id(sock_, &memif_id_);

    if (ret < 0) {
      throw errors::RuntimeException(
          "Error getting next memif id. Could not create memif interface.");
    }

    input_params.id = memif_id_;
    input_params.role = memif_role_t::MASTER;
    input_params.mode = memif_interface_mode_t::MEMIF_INTERFACE_MODE_IP;
    input_params.rx_queues = MemifConnector::kn_s2m_rings;
    input_params.tx_queues = MemifConnector::kn_m2s_rings;
    input_params.ring_size = 1 << MemifConnector::klog2_ring_size;
    input_params.buffer_size = MemifConnector::kbuf_size;

    memif_output_params_t output_params = {0};

    ret = memif_vapi_create_memif(sock_, &input_params, &output_params);

    if (ret < 0) {
      throw errors::RuntimeException(
          "Error creating memif interface in the local VPP forwarder.");
    }

    return output_params.sw_if_index;
  }

  void initMemifConnection() {
    int retry = 20;

    DLOG_IF(INFO, VLOG_IS_ON(2)) << "Connecting to VPP through vapi.";
    vapi_error_e ret = vapi_connect_safe(&sock_, 0);

    while (ret != VAPI_OK && retry > 0) {
      LOG(ERROR) << "Error connecting to VPP through vapi. Retrying..";
      --retry;
      ret = vapi_connect_safe(&sock_, 0);
    }

    CHECK_EQ(ret, VAPI_OK)
        << "Impossible to connect to forwarder. Is VPP running?";

    DLOG_IF(INFO, VLOG_IS_ON(2)) << "Connected to VPP through vapi.";

    sw_if_index_ = getMemifConfiguration();

    DLOG_IF(INFO, VLOG_IS_ON(2))
        << "Creating memif interface in the local VPP forwarder.";
    memif_connector_->connect(memif_id_, 0 /* is_master = false */,
                              memif_socket_filename);

    DLOG_IF(INFO, VLOG_IS_ON(2)) << "Wait for memif to be connected";
    connection_future_.wait();
    CHECK_EQ(connection_future_.get(), true);
  }

  void onPacketReceived(Connector *connector,
                        const std::vector<utils::MemBuf::Ptr> &packets,
                        const std::error_code &ec) {
    uint16_t dst_port;
    std::array<LocalEnpointTable::iterator, Connector::max_burst> connectors;
    int counter = 0;

    if (ec) {
      LOG(ERROR) << "Error receiving packet from memif: " << memif_id_;
      return;
    }

    DCHECK(packets.size() <= Connector::max_burst);

    utils::SpinLock::Acquire locked(connector_lock_);

    LocalEnpointTable::iterator cached_endpoint = local_endpoints_table_.end();
    LocalEnpointTable::iterator it;
    for (auto &_packet : packets) {
      // We need to group packets belonging to local connectors
      // together.
      auto packet = std::static_pointer_cast<Packet>(_packet);
      dst_port = packet->getDstPort();
      if (cached_endpoint != local_endpoints_table_.end() &&
          dst_port == cached_endpoint->first) {
        // fast path
        cached_endpoint->second.second.push_back(packet);
      } else {
        // slow path
        it = local_endpoints_table_.find(dst_port);
        if (TRANSPORT_EXPECT_FALSE(it == local_endpoints_table_.end())) {
          DLOG_IF(INFO, VLOG_IS_ON(3))
              << "Received packet from memif: " << memif_id_
              << " with unknown dst port: " << dst_port;
          continue;
        }

        it->second.second.push_back(packet);
        connectors[counter++] = cached_endpoint = it;
      }
    }

    for (int i = 0; i < counter; i++) {
      it = connectors[i];
      // this cannot fail
      DCHECK(it != local_endpoints_table_.end());

      auto &endpoint = it->second;
      auto &connector = endpoint.first;
      auto &packets = endpoint.second;

      if (TRANSPORT_EXPECT_TRUE(packets.size())) {
        connector->receive(packets);
        packets.clear();
      }
    }
  }
  void onPacketSent(Connector *connector, const std::error_code &ec) {}
  void onConnectorClosed(Connector *connector) {}
  void onConnectorReconnected(Connector *connector) {
    connection_promise_.set_value(true);
  }

  void parseForwarderConfiguration(const libconfig::Setting &io_config,
                                   std::error_code &ec);

 private:
  // TODO check if lock is required
  utils::SpinLock connector_lock_;

  /**
   * Connectors and listeners must be declares *before* thread_pool_, so that
   * threads destructors will wait for them to gracefully close before being
   * destroyed.
   */
  std::unordered_map<Connector::Id, Connector::Ptr> local_connectors_;

  // Memif parameters
  std::shared_ptr<MemifConnector> memif_connector_;
  uint32_t memif_id_;
  uint32_t sw_if_index_;
  // std::vector<ip46_address_t> local_ips_;

  // VAPI socket
  vapi_ctx_t sock_;

  // Endpoint table
  LocalEnpointTable local_endpoints_table_;

  // Random utilities
  std::random_device rd_;
  std::mt19937 mt_;
  std::uniform_int_distribution<uint16_t> dist_;

  // Connection promise/future
  std::promise<bool> connection_promise_;
  std::future<bool> connection_future_;
};

class MemifForwarderGlobal : public ::utils::Singleton<MemifForwarderGlobal> {
  friend class utils::Singleton<MemifForwarderGlobal>;

 public:
  ~MemifForwarderGlobal() {}
  MemifForwarder::Ptr &getReference() { return forwarder_; }

 private:
  MemifForwarderGlobal() : forwarder_(std::make_shared<MemifForwarder>()) {}

 private:
  MemifForwarder::Ptr forwarder_;
};

}  // namespace core

}  // namespace transport
