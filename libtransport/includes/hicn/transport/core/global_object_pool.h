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

#include <hicn/transport/core/packet.h>
#include <hicn/transport/utils/fixed_block_allocator.h>
#include <hicn/transport/utils/singleton.h>

#include <array>
#include <mutex>

namespace transport {

namespace core {

template <std::size_t packet_pool_size = 1024, std::size_t chunk_size = 2048>
class PacketManager : public utils::ThreadLocalSingleton<
                          PacketManager<packet_pool_size, chunk_size>> {
  friend class utils::ThreadLocalSingleton<
      PacketManager<packet_pool_size, chunk_size>>;

 public:
  using MemoryPool = utils::FixedBlockAllocator<chunk_size, packet_pool_size>;
  using RawBuffer = std::pair<uint8_t *, std::size_t>;

  struct PacketStorage {
    std::array<uint8_t, 256> packet_and_shared_ptr;
    std::max_align_t align;
  };

  utils::MemBuf::Ptr getMemBuf() {
    utils::MemBuf *memory = nullptr;

    memory = reinterpret_cast<utils::MemBuf *>(memory_pool_.allocateBlock());

    utils::STLAllocator<utils::MemBuf, MemoryPool> allocator(memory,
                                                             &memory_pool_);
    auto offset = offsetof(PacketStorage, align);
    auto ret = std::allocate_shared<utils::MemBuf>(
        allocator, utils::MemBuf::WRAP_BUFFER, (uint8_t *)memory + offset, 0,
        chunk_size - offset);
    ret->clear();

    return ret;
  }

  utils::MemBuf::Ptr getMemBuf(uint8_t *buffer, std::size_t length) {
    auto offset = offsetof(PacketStorage, align);
    auto memory = buffer - offset;
    utils::STLAllocator<utils::MemBuf, MemoryPool> allocator(
        (utils::MemBuf *)memory, &memory_pool_);
    auto ret = std::allocate_shared<utils::MemBuf>(
        allocator, utils::MemBuf::WRAP_BUFFER, (uint8_t *)buffer, length,
        chunk_size - offset);

    return ret;
  }

  template <
      typename PacketType, typename... Args,
      typename = std::enable_if_t<std::is_base_of<Packet, PacketType>::value>>
  typename PacketType::Ptr getPacket(Args &&...args) {
    static_assert(sizeof(PacketType) + sizeof(std::shared_ptr<PacketType>) +
                      sizeof(std::max_align_t) <=
                  sizeof(PacketStorage::packet_and_shared_ptr));
    PacketType *memory = nullptr;

    memory = reinterpret_cast<PacketType *>(memory_pool_.allocateBlock());
    utils::STLAllocator<PacketType, MemoryPool> allocator(memory,
                                                          &memory_pool_);
    auto offset = offsetof(PacketStorage, align);
    auto ret = std::allocate_shared<PacketType>(
        allocator, PacketType::CREATE, (uint8_t *)memory + offset, 0,
        chunk_size - offset, std::forward<Args>(args)...);

    return ret;
  }

  std::pair<uint8_t *, std::size_t> getRawBuffer() {
    uint8_t *memory = nullptr;
    memory = reinterpret_cast<uint8_t *>(memory_pool_.allocateBlock());

    auto offset = offsetof(PacketStorage, align);
    memory += offset;

    return std::make_pair(memory, chunk_size - offset);
  }

  template <typename PacketType, typename... Args>
  typename PacketType::Ptr getPacketFromExistingBuffer(uint8_t *buffer,
                                                       std::size_t length,
                                                       Args &&...args) {
    auto offset = offsetof(PacketStorage, align);
    auto memory = reinterpret_cast<PacketType *>(buffer - offset);
    utils::STLAllocator<PacketType, MemoryPool> allocator(memory,
                                                          &memory_pool_);
    auto ret = std::allocate_shared<PacketType>(
        allocator, PacketType::WRAP_BUFFER, (uint8_t *)buffer, length,
        chunk_size - offset, std::forward<Args>(args)...);

    return ret;
  }

 private:
  PacketManager(std::size_t size = packet_pool_size)
      : memory_pool_(MemoryPool::getInstance()), size_(0) {}
  MemoryPool &memory_pool_;
  std::atomic<size_t> size_;
};

}  // end namespace core

}  // end namespace transport
