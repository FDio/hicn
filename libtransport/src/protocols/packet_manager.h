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

#include <hicn/transport/utils/object_pool.h>

namespace transport {

namespace protocol {

using namespace core;

template <typename PacketType, std::size_t packet_pool_size = 4096>
class PacketManager {
  static_assert(std::is_base_of<Packet, PacketType>::value,
                "The packet manager support just Interest and Data.");

 public:
  PacketManager(std::size_t size = packet_pool_size) : size_(0) {
    // Create pool of interests
    increasePoolSize(size);
  }

  TRANSPORT_ALWAYS_INLINE void increasePoolSize(std::size_t size) {
    for (std::size_t i = 0; i < size; i++) {
      interest_pool_.add(new PacketType());
    }

    size_ += size;
  }

  TRANSPORT_ALWAYS_INLINE typename PacketType::Ptr getPacket() {
    auto result = interest_pool_.get();

    while (TRANSPORT_EXPECT_FALSE(!result.first)) {
      // Add packets to the pool
      increasePoolSize(size_);
      result = interest_pool_.get();
    }

    result.second->resetPayload();
    return std::move(result.second);
  }

 private:
  utils::ObjectPool<PacketType> interest_pool_;
  std::size_t size_;
};

}  // end namespace protocol

}  // end namespace transport
