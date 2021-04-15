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

#include <hicn/transport/core/connector_stats.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/endpoint.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/core/interest.h>
#include <hicn/transport/core/packet.h>
#include <hicn/transport/portability/platform.h>
#include <hicn/transport/utils/membuf.h>
#include <hicn/transport/utils/object_pool.h>
#include <hicn/transport/utils/ring_buffer.h>
#include <hicn/transport/utils/shared_ptr_utils.h>

#include <deque>
#include <functional>

namespace transport {

namespace core {

class Connector : public std::enable_shared_from_this<Connector> {
 public:
  enum class Type : uint8_t {
    SOCKET_CONNECTOR,
    MEMIF_CONNECTOR,
    LOOPBACK_CONNECTOR,
  };

  enum class State : std::uint8_t {
    CLOSED,
    CONNECTING,
    CONNECTED,
  };

  enum class Role : std::uint8_t { CONSUMER, PRODUCER };

 public:
  static constexpr std::size_t queue_size = 4096;
  static constexpr std::uint32_t invalid_connector = ~0;

#ifdef LINUX
  static constexpr std::uint16_t max_burst = 256;
#endif

  using Ptr = std::shared_ptr<Connector>;
  using PacketQueue = std::deque<Packet::Ptr>;
  using PacketReceivedCallback = std::function<void(
      Connector *, utils::MemBuf &, const std::error_code &)>;
  using PacketSentCallback =
      std::function<void(Connector *, const std::error_code &)>;
  using OnCloseCallback = std::function<void(Connector *)>;
  using OnReconnectCallback = std::function<void(Connector *)>;
  using Id = std::uint64_t;

  template <typename ReceiveCallback, typename SentCallback, typename OnClose,
            typename OnReconnect>
  Connector(ReceiveCallback &&receive_callback, SentCallback &&packet_sent,
            OnClose &&close_callback, OnReconnect &&on_reconnect)
      : receive_callback_(std::forward<ReceiveCallback &&>(receive_callback)),
        sent_callback_(std::forward<SentCallback &&>(packet_sent)),
        on_close_callback_(std::forward<OnClose &&>(close_callback)),
        on_reconnect_callback_(std::forward<OnReconnect &&>(on_reconnect)),
        state_(State::CLOSED),
        connector_id_(invalid_connector) {}

  virtual ~Connector(){};

  template <typename ReceiveCallback>
  void setReceiveCallback(ReceiveCallback &&callback) {
    receive_callback_ = std::forward<ReceiveCallback &&>(callback);
  }

  template <typename SentCallback>
  void setSentCallback(SentCallback &&callback) {
    sent_callback_ = std::forward<SentCallback &&>(callback);
  }

  template <typename OnClose>
  void setOnCloseCallback(OnClose &&callback) {
    on_close_callback_ = std::forward<OnClose &&>(callback);
  }

  template <typename OnReconnect>
  void setReconnectCallback(const OnReconnect &&callback) {
    on_reconnect_callback_ = std::forward<OnReconnect>(callback);
  }

  const PacketReceivedCallback &getReceiveCallback() const {
    return receive_callback_;
  }

  const PacketSentCallback &getSentCallback() { return sent_callback_; }

  const OnCloseCallback &getOnCloseCallback() { return on_close_callback_; }

  const OnReconnectCallback &getOnReconnectCallback() {
    return on_reconnect_callback_;
  }

  virtual void send(Packet &packet) = 0;

  virtual void send(const uint8_t *packet, std::size_t len) = 0;

  virtual void close() = 0;

  virtual State state() { return state_; };

  virtual bool isConnected() { return state_ == State::CONNECTED; }

  void setConnectorId(Id connector_id) { connector_id_ = connector_id; }

  Id getConnectorId() { return connector_id_; }

  void setConnectorName(std::string connector_name) {
    connector_name_ = connector_name;
  }

  std::string getConnectorName() { return connector_name_; }

  Endpoint getLocalEndpoint() { return local_endpoint_; }

  Endpoint getRemoteEndpoint() { return remote_endpoint_; }

  void setRole(Role r) { role_ = r; }

  Role getRole() { return role_; }

  static utils::MemBuf::Ptr getPacketFromBuffer(uint8_t *buffer,
                                                std::size_t size) {
    utils::MemBuf::Ptr ret;

    auto format = Packet::getFormatFromBuffer(buffer, size);

    if (TRANSPORT_EXPECT_TRUE(format != HF_UNSPEC && !_is_icmp(format))) {
      if (Packet::isInterest(buffer)) {
        ret = core::PacketManager<>::getInstance()
                  .getPacketFromExistingBuffer<Interest>(buffer, size);
      } else {
        ret = core::PacketManager<>::getInstance()
                  .getPacketFromExistingBuffer<ContentObject>(buffer, size);
      }
    } else {
      ret = core::PacketManager<>::getInstance().getMemBuf(buffer, size);
    }

    return ret;
  }

  static std::pair<uint8_t *, std::size_t> getRawBuffer() {
    return core::PacketManager<>::getInstance().getRawBuffer();
  }

 protected:
  inline void sendSuccess(const utils::MemBuf &packet) {
    stats_.tx_packets_.fetch_add(1, std::memory_order_relaxed);
    stats_.tx_bytes_.fetch_add(packet.length(), std::memory_order_relaxed);
  }

  inline void receiveSuccess(const utils::MemBuf &packet) {
    stats_.rx_packets_.fetch_add(1, std::memory_order_relaxed);
    stats_.rx_bytes_.fetch_add(packet.length(), std::memory_order_relaxed);
  }

  inline void sendFailed() {
    stats_.drops_.fetch_add(1, std::memory_order_relaxed);
  }

 protected:
  PacketQueue output_buffer_;

  // Connector events
  PacketReceivedCallback receive_callback_;
  PacketSentCallback sent_callback_;
  OnCloseCallback on_close_callback_;
  OnReconnectCallback on_reconnect_callback_;

  // Connector state
  std::atomic<State> state_;
  Id connector_id_;

  // Endpoints
  Endpoint local_endpoint_;
  Endpoint remote_endpoint_;

  // Connector name
  std::string connector_name_;

  // Connector role
  Role role_;

  // Stats
  AtomicConnectorStats stats_;
};

}  // namespace core
}  // namespace transport
