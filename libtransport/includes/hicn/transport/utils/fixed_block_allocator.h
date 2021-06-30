/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#pragma once

#include <hicn/transport/portability/c_portability.h>
#include <hicn/transport/utils/singleton.h>
#include <hicn/transport/utils/spinlock.h>
#include <stdint.h>

#include <cassert>
#include <cstdlib>
#include <memory>

namespace utils {
template <std::size_t SIZE = 512, std::size_t OBJECTS = 4096>
class FixedBlockAllocator
    : public utils::Singleton<FixedBlockAllocator<SIZE, OBJECTS>> {
  friend class utils::Singleton<FixedBlockAllocator<SIZE, OBJECTS>>;

 public:
  ~FixedBlockAllocator() {
    for (auto& p : p_pools_) {
      delete[] p;
    }
  }

  void* allocateBlock(size_t size = SIZE) {
    assert(size <= SIZE);
    uint32_t index;

    SpinLock::Acquire locked(lock_);
    void* p_block = pop();
    if (!p_block) {
      if (TRANSPORT_EXPECT_FALSE(current_pool_index_ >= max_objects_)) {
        // Allocate new memory block
        p_pools_.emplace_front(
            new typename std::aligned_storage<SIZE>::type[max_objects_]);
        // reset current_pool_index_
        current_pool_index_ = 0;
      }

      auto& latest = p_pools_.front();
      index = current_pool_index_++;
      blocks_in_use_++;
      allocations_++;
      p_block = (void*)&latest[index];
    }

    return p_block;
  }

  void deallocateBlock(void* pBlock) {
    SpinLock::Acquire locked(lock_);
    push(pBlock);
    blocks_in_use_--;
    deallocations_++;
  }

 public:
  std::size_t blockSize() { return block_size_; }

  uint32_t blockCount() { return block_count_; }

  uint32_t blocksInUse() { return blocks_in_use_; }

  uint32_t allocations() { return allocations_; }

  uint32_t deallocations() { return deallocations_; }

 private:
  FixedBlockAllocator()
      : block_size_(SIZE),
        object_size_(SIZE),
        max_objects_(OBJECTS),
        p_head_(NULL),
        current_pool_index_(0),
        block_count_(0),
        blocks_in_use_(0),
        allocations_(0),
        deallocations_(0) {
    static_assert(SIZE >= sizeof(long*), "SIZE must be at least 8 bytes");
    p_pools_.emplace_front(
        new typename std::aligned_storage<SIZE>::type[max_objects_]);
  }

  void push(void* p_memory) {
    Block* p_block = (Block*)p_memory;
    p_block->p_next = p_head_;
    p_head_ = p_block;
  }

  void* pop() {
    Block* p_block = nullptr;

    if (p_head_) {
      p_block = p_head_;
      p_head_ = p_head_->p_next;
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
  uint32_t current_pool_index_;
  std::list<typename std::aligned_storage<SIZE>::type*> p_pools_;
  uint32_t block_count_;
  uint32_t blocks_in_use_;
  uint32_t allocations_;
  uint32_t deallocations_;

  SpinLock lock_;
};

template <std::size_t A, std::size_t B>
std::unique_ptr<FixedBlockAllocator<A, B>>
    FixedBlockAllocator<A, B>::instance_ = nullptr;

/**
 * STL Allocator trait to be used with allocate_shared.
 */
template <typename T, typename Pool>
class STLAllocator {
  /**
   * If STLAllocator is rebound to another type (!= T) using copy constructor,
   * we may need to access private members of the source allocator to copy
   * memory and pool.
   */
  template <typename U, typename P>
  friend class STLAllocator;

 public:
  using size_type = std::size_t;
  using difference_type = ptrdiff_t;
  using pointer = T*;
  using const_pointer = const T*;
  using reference = T&;
  using const_reference = const T&;
  using value_type = T;

  STLAllocator(pointer memory, Pool* memory_pool)
      : memory_(memory), pool_(memory_pool) {}

  ~STLAllocator() {}

  template <typename U>
  STLAllocator(const STLAllocator<U, Pool>& other) {
    memory_ = other.memory_;
    pool_ = other.pool_;
  }

  template <typename U>
  struct rebind {
    typedef STLAllocator<U, Pool> other;
  };

  pointer address(reference x) const { return &x; }
  const_pointer address(const_reference x) const { return &x; }

  pointer allocate(size_type n, pointer hint = 0) {
    return static_cast<pointer>(memory_);
  }

  void deallocate(pointer p, size_type n) { pool_->deallocateBlock(memory_); }

  template <typename... Args>
  void construct(pointer p, Args&&... args) {
    new (static_cast<pointer>(p)) T(std::forward<Args>(args)...);
  }

  void destroy(pointer p) { p->~T(); }

 private:
  void* memory_;
  Pool* pool_;
};

template <typename T, typename U, typename V>
inline bool operator==(const STLAllocator<T, V>&, const STLAllocator<U, V>&) {
  return true;
}

template <typename T, typename U, typename V>
inline bool operator!=(const STLAllocator<T, V>& a,
                       const STLAllocator<U, V>& b) {
  return !(a == b);
}

}  // namespace utils