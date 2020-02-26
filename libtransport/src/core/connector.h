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

#include <hicn/transport/core/packet.h>
#include <hicn/transport/utils/membuf.h>
#include <hicn/transport/utils/object_pool.h>
#include <hicn/transport/utils/ring_buffer.h>

#include <deque>
#include <functional>

namespace transport {

namespace core {

enum class ConnectorType : uint8_t {
  SOCKET_CONNECTOR,
  RAW_SOCKET_CONNECTOR,
  VPP_CONNECTOR,
};

class Connector {
 protected:
  enum class ConnectorState {
    CLOSED,
    CONNECTING,
    CONNECTED,
  };

 public:
  static constexpr std::size_t packet_size = 2048;
  static constexpr std::size_t queue_size = 4096;
  static constexpr std::size_t packet_pool_size = 4096;

  using PacketRing = utils::CircularFifo<Packet::MemBufPtr, queue_size>;
  using PacketQueue = std::deque<Packet::MemBufPtr>;
  using PacketReceivedCallback = std::function<void(Packet::MemBufPtr &&)>;
  using OnReconnect = std::function<void()>;
  using PacketSentCallback = std::function<void()>;

  Connector(PacketReceivedCallback &&receive_callback,
            OnReconnect &&reconnect_callback);

  virtual ~Connector(){};

  virtual void send(const Packet::MemBufPtr &packet) = 0;

  virtual void send(const uint8_t *packet, std::size_t len,
                    const PacketSentCallback &packet_sent = 0) = 0;

  virtual void close() = 0;

  virtual ConnectorState state() { return state_; };

  virtual bool isConnected() { return state_ == ConnectorState::CONNECTED; }

 protected:
  void increasePoolSize(std::size_t size = packet_pool_size);

  TRANSPORT_ALWAYS_INLINE utils::ObjectPool<utils::MemBuf>::Ptr getPacket() {
    auto result = packet_pool_.get();

    while (TRANSPORT_EXPECT_FALSE(!result.first)) {
      // Add packets to the pool
      increasePoolSize();
      result = packet_pool_.get();
    }

    if (result.second->isChained()) {
      result.second->separateChain(result.second->next(),
                                   result.second->prev());
    }

    result.second->trimEnd(result.second->length());
    return std::move(result.second);
  }

 private:
  void init();

 protected:
  static std::once_flag init_flag_;
  utils::ObjectPool<utils::MemBuf> packet_pool_;
  PacketQueue output_buffer_;

  // Connector events
  PacketReceivedCallback receive_callback_;
  OnReconnect on_reconnect_callback_;

  // Connector state
  ConnectorState state_;
};
}  // end namespace core

}  // end namespace transport
