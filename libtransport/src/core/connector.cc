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

#include <core/connector.h>

namespace transport {

namespace core {

std::once_flag Connector::init_flag_;

Connector::Connector(PacketReceivedCallback &&receive_callback,
                     OnReconnect &&reconnect_callback)
    : packet_pool_(),
      receive_callback_(std::move(receive_callback)),
      on_reconnect_callback_(std::move(reconnect_callback)),
      state_(ConnectorState::CLOSED) {
  init();
}

void Connector::init() { increasePoolSize(); }

void Connector::increasePoolSize(std::size_t size) {
  // Allocate space for receiving packets
  const auto capacity = packet_size * size;
  uint8_t *buffer = static_cast<uint8_t *>(malloc(capacity));
  std::unique_ptr<utils::MemBuf> buffer0 =
      utils::MemBuf::takeOwnership(buffer, capacity, 0, nullptr, nullptr, true);

  for (std::size_t i = 1; i < size; i++) {
    auto b = buffer0->cloneOne();
    b->advance(i * packet_size);
    packet_pool_.add(b.release());
  }
}

}  // end namespace core

}  // end namespace transport
