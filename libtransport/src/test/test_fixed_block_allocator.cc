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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hicn/transport/core/global_object_pool.h>
#include <hicn/transport/utils/event_thread.h>
#include <hicn/transport/utils/fixed_block_allocator.h>

namespace utils {

class FixedBlockAllocatorTest : public ::testing::Test {
 protected:
  static inline const std::size_t default_size = 2048;
  static inline const std::size_t default_n_buffer = 1024;

  // Get fixed block allocator_ of 1024 buffers of size 2048 bytes
  FixedBlockAllocatorTest()
      : allocator_(
            ::utils::FixedBlockAllocator<default_size,
                                         default_n_buffer>::getInstance()) {
    // You can do set-up work for each test here.
  }

  virtual ~FixedBlockAllocatorTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {
    // Code here will be called immediately after the constructor (right
    // before each test).
    allocator_.reset();
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test (right
    // before the destructor).
    allocator_.reset();
  }

  static bool pointerIsAligned(const void *pointer, size_t byte_count) {
    // Sanity check
    EXPECT_THAT(reinterpret_cast<std::uintptr_t>(pointer) &
                    (alignof(std::max_align_t) - 1),
                testing::Eq(std::uintptr_t(0)));

    return uintptr_t(pointer) % byte_count == 0;
  }

  ::utils::FixedBlockAllocator<default_size, default_n_buffer> &allocator_;
};

TEST_F(FixedBlockAllocatorTest, DefaultChecks) {
  EXPECT_EQ(allocator_.blockSize(), default_size);
  EXPECT_EQ(allocator_.blockCount(), default_n_buffer);
  EXPECT_EQ(allocator_.allocations(), 0UL);
  EXPECT_EQ(allocator_.deallocations(), 0UL);
  EXPECT_EQ(allocator_.blocksInUse(), 0UL);

  // Allocate one single block of memory
  auto block = allocator_.allocateBlock();

  ASSERT_THAT(block, testing::NotNull());

  // Check statistics
  EXPECT_EQ(allocator_.allocations(), 1UL);
  EXPECT_EQ(allocator_.deallocations(), 0UL);
  EXPECT_EQ(allocator_.blocksInUse(), 1UL);

  // Deallocate it
  allocator_.deallocateBlock(block);

  // check statistics
  EXPECT_EQ(allocator_.allocations(), 1UL);
  EXPECT_EQ(allocator_.deallocations(), 1UL);
  EXPECT_EQ(allocator_.blocksInUse(), 0UL);

  // Test reset
  allocator_.reset();

  EXPECT_EQ(allocator_.blockSize(), default_size);
  EXPECT_EQ(allocator_.blockCount(), default_n_buffer);
  EXPECT_EQ(allocator_.allocations(), 0UL);
  EXPECT_EQ(allocator_.deallocations(), 0UL);
  EXPECT_EQ(allocator_.blocksInUse(), 0UL);
}

TEST_F(FixedBlockAllocatorTest, CheckMemoryIsReused) {
  // Get one block. As it is the first one, it will be retrieved from the pool
  auto block = allocator_.allocateBlock();

  // Make sure block is valid
  ASSERT_THAT(block, testing::NotNull());

  // Release block
  allocator_.deallocateBlock(block);

  // Get same memory block again
  auto block2 = allocator_.allocateBlock();

  // Make sure memory is reused
  ASSERT_EQ(block, block2);

  // Get a third block
  auto block3 = allocator_.allocateBlock();

  // Make sure is different memory
  ASSERT_NE(block2, block3);

  // Deallocate both and check we get back the laso one
  allocator_.deallocateBlock(block2);
  allocator_.deallocateBlock(block3);

  auto block4 = allocator_.allocateBlock();
  ASSERT_EQ(block3, block4);
}

TEST_F(FixedBlockAllocatorTest, CheckMemoryIsContiguous) {
  // Get one block. As it is the first one, it will be retrieved from the pool
  auto block = reinterpret_cast<uint8_t *>(allocator_.allocateBlock());

  // Make sure block is valid
  ASSERT_THAT(block, testing::NotNull());

  // Get another block
  auto block2 = reinterpret_cast<uint8_t *>(allocator_.allocateBlock());

  // Make sure block is valid
  ASSERT_THAT(block2, testing::NotNull());

  // Check the 2 blocks come from contiguous memory
  ASSERT_THAT(std::size_t(block2 - block), testing::Eq(default_size));
}

TEST_F(FixedBlockAllocatorTest, CheckPoolExpansion) {
  // Get all the blocks we setup when constructing the allocator
  std::array<uint8_t *, default_n_buffer> blocks;
  blocks[0] = reinterpret_cast<uint8_t *>(allocator_.allocateBlock());
  for (std::size_t i = 1; i < default_n_buffer; i++) {
    blocks[i] = reinterpret_cast<uint8_t *>(allocator_.allocateBlock());
    ASSERT_THAT(std::size_t(blocks[i] - blocks[i - 1]),
                testing::Eq(default_size));
  }

  ASSERT_THAT(allocator_.blockCount(), testing::Eq(default_n_buffer));

  // We should have finished all the blocks belonging to first pool. Let's get
  // one additional block
  auto new_block = reinterpret_cast<uint8_t *>(allocator_.allocateBlock());

  // Make sure the block count doubled its size
  ASSERT_THAT(allocator_.blockCount(), testing::Eq(2 * default_n_buffer));

  // Check the new block is not contiguous with respect last block in blocks
  ASSERT_THAT(std::size_t(new_block - blocks[default_n_buffer - 1]),
              testing::Ne(default_size));
}

TEST_F(FixedBlockAllocatorTest, CheckMemoryIsAligned) {
  for (std::size_t i = 0; i < default_n_buffer; i++) {
    auto block = reinterpret_cast<uint8_t *>(allocator_.allocateBlock());
    ASSERT_THAT(pointerIsAligned(block, alignof(std::max_align_t)),
                testing::IsTrue);
  }
}

TEST_F(FixedBlockAllocatorTest, Multithreading) {
  // Create 4 threads
  utils::EventThread threads[4];
  ::utils::FixedBlockAllocator<default_size, default_n_buffer>
      *allocator_addresses[4] = {nullptr, nullptr, nullptr, nullptr};
  int i = 0;
  for (auto &t : threads) {
    t.add([&allocator_addresses, i]() {
      auto &allocator =
          ::utils::FixedBlockAllocator<default_size,
                                       default_n_buffer>::getInstance();
      allocator_addresses[i] = &allocator;
    });
    i++;
  }

  // Stop threads
  for (auto &t : threads) {
    t.stop();
  }

  // Check the instance of allocator was different for each thread
  for (int i = 0; i < 4; i++) {
    for (int j = i + 1; j < 4; j++) {
      ASSERT_NE(allocator_addresses[i], allocator_addresses[j]);
    }
  }
}

}  // namespace utils