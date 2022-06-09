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

#include <glog/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/interest.h>
#define ALLOCATION_CHECKS
#include <hicn/transport/core/global_object_pool.h>
#undef ALLOCATION_CHECKS
#include <hicn/transport/utils/chrono_typedefs.h>
#include <hicn/transport/utils/event_thread.h>

namespace transport {
namespace core {

class PacketAllocatorTest : public ::testing::Test {
 protected:
  static inline const std::size_t default_size = 2048;
  static inline const std::size_t default_n_buffer = 1024;
  static inline const std::size_t counter = 1024;
  static inline const std::size_t total_packets = 1024 * counter;

  // Get fixed block allocator_ of 1024 buffers of size 2048 bytes
  PacketAllocatorTest() : allocator_(PacketManager<>::getInstance()) {
    // You can do set-up work for each test here.
  }

  virtual ~PacketAllocatorTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {}

  virtual void TearDown() {}

  static bool pointerIsAligned(const void *pointer, size_t byte_count) {
    return uintptr_t(pointer) % byte_count == 0;
  }

  template <typename T, typename... Args>
  void allocationTest(Args &&...args) {
    // Create packet
    auto packet = allocator_.getPacket<T>(std::forward<Args>(args)...);

    // Check boundaries
    LOG(INFO) << "packet size: " << sizeof(*packet) + sizeof(packet)
              << std::endl;
    EXPECT_LE(sizeof(*packet) + sizeof(packet) + sizeof(std::max_align_t),
              sizeof(PacketManager<>::PacketStorage::packet_and_shared_ptr));
  }

  PacketManager<> &allocator_;
};

TEST_F(PacketAllocatorTest, ContentObjectAllocation) {
  allocationTest<core::ContentObject>(HF_INET_TCP);
}

TEST_F(PacketAllocatorTest, InterestAllocation) {
  allocationTest<core::Interest>(HF_INET_TCP);
}

// TEST_F(PacketAllocatorTest, MemBufAllocation) {
//   allocationTest<::utils::MemBuf>();
// }

TEST_F(PacketAllocatorTest, CheckAllocationIsCorrect) {
  // Create packet
  auto packet = allocator_.getPacket<core::ContentObject>(HF_INET_TCP);

  // Address of actual buffer
  uint8_t *buffer_address = packet->writableData();

  // Address of packet
  uint8_t *packet_address = reinterpret_cast<uint8_t *>(packet.get());

  uint8_t *start_address =
      buffer_address -
      sizeof(PacketManager<>::PacketStorage::packet_and_shared_ptr);

  // Check memory was allocated on correct positions
  EXPECT_TRUE(pointerIsAligned(start_address, alignof(std::max_align_t)));
  EXPECT_TRUE(packet_address > start_address &&
              packet_address < buffer_address);
  EXPECT_TRUE(pointerIsAligned(buffer_address, alignof(std::max_align_t)));
  EXPECT_THAT(std::size_t(buffer_address - start_address),
              testing::Eq(sizeof(
                  PacketManager<>::PacketStorage::packet_and_shared_ptr)));
}

TEST_F(PacketAllocatorTest, CheckAllocationSpeed) {
  // Check time needed to allocate 1 million packeauto &packet_manager =
  auto &packet_manager = core::PacketManager<>::getInstance();

  // Send 1 million packets
  std::array<utils::MemBuf::Ptr, counter> packets;
  auto t0 = utils::SteadyTime::now();
  std::size_t sum = 0;
  for (std::size_t j = 0; j < counter; j++) {
    for (std::size_t i = 0; i < counter; i++) {
      packets[i] = packet_manager.getMemBuf();
      sum++;
    }
  }
  auto t1 = utils::SteadyTime::now();

  auto delta = utils::SteadyTime::getDurationUs(t0, t1);
  auto rate = double(sum) * 1000000.0 / double(delta.count());

  LOG(INFO) << "rate: " << rate << " packets/s";
}

}  // namespace core
}  // namespace transport