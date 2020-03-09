/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#pragma once

#include <hicn/transport/portability/c_portability.h>
#include <hicn/transport/utils/spinlock.h>

#include <stdint.h>
#include <cstdlib>
#include <memory>
#include <cassert>

namespace utils {
template <std::size_t DEFAULT_SIZE = 512, std::size_t OBJECTS = 4096>
class FixedBlockAllocator {
  FixedBlockAllocator(std::size_t size = DEFAULT_SIZE,
                      std::size_t objects = OBJECTS)
      : block_size_(size < sizeof(void*) ? sizeof(long*) : size),
        object_size_(size),
        max_objects_(objects),
        p_head_(NULL),
        pool_index_(0),
        block_count_(0),
        blocks_in_use_(0),
        allocations_(0),
        deallocations_(0) {
    p_pool_ = (uint8_t*)new uint8_t[block_size_ * max_objects_];
  }

 public:
  static FixedBlockAllocator* getInstance() {
    if (!instance_) {
      instance_ = std::unique_ptr<FixedBlockAllocator>(
          new FixedBlockAllocator(DEFAULT_SIZE, OBJECTS));
    }

    return instance_.get();
  }

  ~FixedBlockAllocator() { delete[] p_pool_; }

  TRANSPORT_ALWAYS_INLINE void* allocateBlock(size_t size = DEFAULT_SIZE) {
    assert(size <= DEFAULT_SIZE);
    uint32_t index;

    void* p_block = pop();
    if (!p_block) {
      if (pool_index_ < max_objects_) {
        {
          SpinLock::Acquire locked(lock_);
          index = pool_index_++;
        }
        p_block = (void*)(p_pool_ + (index * block_size_));
      } else {
        // TODO Consider increasing pool here instead of throwing an exception
        throw std::runtime_error("No more memory available from packet pool!");
      }
    }

    blocks_in_use_++;
    allocations_++;

    return p_block;
  }

  TRANSPORT_ALWAYS_INLINE void deallocateBlock(void* pBlock) {
    push(pBlock);
    {
      SpinLock::Acquire locked(lock_);
      blocks_in_use_--;
      deallocations_++;
    }
  }

  TRANSPORT_ALWAYS_INLINE std::size_t blockSize() { return block_size_; }

  TRANSPORT_ALWAYS_INLINE uint32_t blockCount() { return block_count_; }

  TRANSPORT_ALWAYS_INLINE uint32_t blocksInUse() { return blocks_in_use_; }

  TRANSPORT_ALWAYS_INLINE uint32_t allocations() { return allocations_; }

  TRANSPORT_ALWAYS_INLINE uint32_t deallocations() { return deallocations_; }

 private:
  TRANSPORT_ALWAYS_INLINE void push(void* p_memory) {
    Block* p_block = (Block*)p_memory;
    {
      SpinLock::Acquire locked(lock_);
      p_block->p_next = p_head_;
      p_head_ = p_block;
    }
  }

  TRANSPORT_ALWAYS_INLINE void* pop() {
    Block* p_block = nullptr;

    {
      SpinLock::Acquire locked(lock_);
      if (p_head_) {
        p_block = p_head_;
        p_head_ = p_head_->p_next;
      }
    }

    return (void*)p_block;
  }

  struct Block {
    Block* p_next;
  };

  static std::unique_ptr<FixedBlockAllocator> instance_;

  const std::size_t block_size_;
  const std::size_t object_size_;
  const std::size_t max_objects_;

  Block* p_head_;
  uint8_t* p_pool_;
  uint32_t pool_index_;
  uint32_t block_count_;
  uint32_t blocks_in_use_;
  uint32_t allocations_;
  uint32_t deallocations_;

  SpinLock lock_;
};

template <std::size_t A, std::size_t B>
std::unique_ptr<FixedBlockAllocator<A, B>>
    FixedBlockAllocator<A, B>::instance_ = nullptr;

}  // namespace utils