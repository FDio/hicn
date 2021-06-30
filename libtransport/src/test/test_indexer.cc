
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

#include <gtest/gtest.h>
#include <protocols/incremental_indexer_bytestream.h>
#include <protocols/indexer.h>
#include <protocols/rtc/rtc_indexer.h>

#include <algorithm>
#include <iostream>
#include <random>

namespace transport {
namespace protocol {

class IncrementalIndexerTest : public ::testing::Test {
 protected:
  IncrementalIndexerTest() : indexer_(nullptr, nullptr) {
    // You can do set-up work for each test here.
  }

  virtual ~IncrementalIndexerTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {
    // Code here will be called immediately after the constructor (right
    // before each test).
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }

  IncrementalIndexer indexer_;
};

class RtcIndexerTest : public ::testing::Test {
 protected:
  RtcIndexerTest() : indexer_(nullptr, nullptr) {
    // You can do set-up work for each test here.
  }

  virtual ~RtcIndexerTest() {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void SetUp() {
    // Code here will be called immediately after the constructor (right
    // before each test).
    indexer_.setFirstSuffix(0);
    indexer_.reset();
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }

  static const constexpr uint32_t LIMIT = (1 << 31);
  rtc::RtcIndexer<LIMIT> indexer_;
};

void testIncrement(Indexer &indexer) {
  // As a first index we should get zero
  auto index = indexer.getNextSuffix();
  EXPECT_EQ(index, uint32_t(0));

  // Check if the sequence works for consecutive incremental numbers
  for (uint32_t i = 1; i < 4096; i++) {
    index = indexer.getNextSuffix();
    EXPECT_EQ(index, i);
  }

  index = indexer.getNextSuffix();
  EXPECT_NE(index, uint32_t(0));
}

void testJump(Indexer &indexer) {
  // Fist suffix is 0
  auto index = indexer.getNextSuffix();
  EXPECT_EQ(index, uint32_t(0));

  // Next suffix should be 1, but we jump to 12345
  uint32_t jump = 12345;
  indexer.jumpToIndex(jump);

  // This takes place immediately
  index = indexer.getNextSuffix();
  EXPECT_EQ(index, jump);
}

TEST_F(IncrementalIndexerTest, TestReset) {
  testIncrement(indexer_);

  // Reset the indexer
  indexer_.reset();

  // Now it should startfrom zero again
  for (uint32_t i = 0; i < 4096; i++) {
    auto index = indexer_.getNextSuffix();
    EXPECT_EQ(index, i);
  }
}

TEST_F(IncrementalIndexerTest, TestGetSuffix) { testIncrement(indexer_); }

TEST_F(IncrementalIndexerTest, TestGetNextReassemblySegment) {
  // Test suffixes for reassembly are not influenced by download suffixed
  // increment
  for (uint32_t i = 0; i < 4096; i++) {
    auto index = indexer_.getNextSuffix();
    EXPECT_EQ(index, i);
  }

  for (uint32_t i = 0; i < 4096; i++) {
    auto index = indexer_.getNextReassemblySegment();
    EXPECT_EQ(index, i);
  }
}

TEST_F(IncrementalIndexerTest, TestJumpToIndex) { testJump(indexer_); }

TEST_F(IncrementalIndexerTest, TestGetFinalSuffix) {
  // Since final suffix hasn't been discovered, it should be invalid_index
  auto final_suffix = indexer_.getFinalSuffix();
  ASSERT_EQ(final_suffix, Indexer::invalid_index);
}

TEST_F(IncrementalIndexerTest, TestMaxLimit) {
  // Jump to max value for uint32_t
  indexer_.jumpToIndex(std::numeric_limits<uint32_t>::max());
  auto ret = indexer_.getNextSuffix();
  ASSERT_EQ(ret, Indexer::invalid_index);

  // Now the indexer should always return invalid_index
  for (uint32_t i = 0; i < 4096; i++) {
    ret = indexer_.getNextSuffix();
    EXPECT_EQ(ret, Indexer::invalid_index);
  }
}

TEST_F(IncrementalIndexerTest, TestSetFirstSuffix) {
  // Set first suffix before starting
  uint32_t start = 1234567890;
  indexer_.setFirstSuffix(1234567890);

  // The first suffix set should take place only after a reset
  auto index = indexer_.getNextSuffix();
  EXPECT_EQ(index, uint32_t(0));

  indexer_.reset();
  index = indexer_.getNextSuffix();
  EXPECT_EQ(index, start);
}

TEST_F(IncrementalIndexerTest, TestIsFinalSuffixDiscovered) {
  // Final suffix should not be discovererd
  auto ret = indexer_.isFinalSuffixDiscovered();
  EXPECT_FALSE(ret);
}

TEST_F(RtcIndexerTest, TestReset) {
  // Without setting anything this indexer should behave exactly as the
  // incremental indexer for the getNextSuffix()
  testIncrement(indexer_);

  // Reset the indexer
  indexer_.reset();

  // Now it should startfrom zero again
  for (uint32_t i = 0; i < 4096; i++) {
    auto index = indexer_.getNextSuffix();
    EXPECT_EQ(index, i);
  }
}

TEST_F(RtcIndexerTest, TestGetNextSuffix) {
  // Without setting anything this indexer should behave exactly as the
  // incremental indexer for the getNextSuffix()
  testIncrement(indexer_);
}

TEST_F(RtcIndexerTest, TestGetNextReassemblySegment) {
  // This indexer should not provide reassembly segments since they are not
  // required for rtc
  try {
    indexer_.getNextReassemblySegment();
    // We should not reach this point
    FAIL() << "Exception expected here";
  } catch (const errors::RuntimeException &exc) {
    // OK correct exception
  } catch (...) {
    FAIL() << "Wrong exception thrown";
  }
}

TEST_F(RtcIndexerTest, TestGetFinalSuffix) {
  // Final suffix should be eqaul to LIMIT
  ASSERT_EQ(indexer_.getFinalSuffix(), uint32_t(LIMIT));
}

TEST_F(RtcIndexerTest, TestJumpToIndex) { testJump(indexer_); }

TEST_F(RtcIndexerTest, TestIsFinalSuffixDiscovered) {
  // This method should always return true
  EXPECT_TRUE(indexer_.isFinalSuffixDiscovered());
}

TEST_F(RtcIndexerTest, TestMaxLimit) {
  // Once reached the LIMIT, this indexer should restart from 0

  // Jump to max value for uint32_t
  indexer_.jumpToIndex(LIMIT);
  testIncrement(indexer_);
}

TEST_F(RtcIndexerTest, TestEnableFec) {
  // Here we enable the FEC and we check we receive indexes for souece packets
  // only
  indexer_.enableFec(fec::FECType::RS_K1_N3);

  // We did not set NFec, which should be zero. So we get only indexes for
  // Source packets.

  // With this FEC type we should get one source packet every 3 (0 . . 3 . . 6)
  auto index = indexer_.getNextSuffix();
  EXPECT_EQ(index, uint32_t(0));

  index = indexer_.getNextSuffix();
  EXPECT_EQ(index, uint32_t(3));

  index = indexer_.getNextSuffix();
  EXPECT_EQ(index, uint32_t(6));

  // Change FEC Type
  indexer_.enableFec(fec::FECType::RS_K10_N30);

  // With this FEC type we should get source packets from 7 to 9
  for (uint32_t i = 7; i < 10; i++) {
    index = indexer_.getNextSuffix();
    EXPECT_EQ(index, i);
  }

  // And then jump to 30
  index = indexer_.getNextSuffix();
  EXPECT_EQ(index, uint32_t(30));

  // Let's now jump to a high value
  indexer_.jumpToIndex(12365);
  for (uint32_t i = 12365; i < 12369; i++) {
    index = indexer_.getNextSuffix();
    EXPECT_EQ(index, i);
  }
}

TEST_F(RtcIndexerTest, TestSetNFec) {
  // Here we enable the FEC and we set a max of 20 fec packets
  indexer_.enableFec(fec::FECType::RS_K10_N90);
  indexer_.setNFec(20);

  // We should get indexes up to 29
  uint32_t index;
  for (uint32_t i = 0; i < 30; i++) {
    index = indexer_.getNextSuffix();
    EXPECT_EQ(i, index);
  }

  // Then it should jump to 90
  for (uint32_t i = 90; i < 99; i++) {
    index = indexer_.getNextSuffix();
    EXPECT_EQ(i, index);
  }

  // Let's set NFEC > 80
  indexer_.setNFec(150);
}

TEST_F(RtcIndexerTest, TestSetNFecWithOffset) {
  // Here we enable the FEC and we set a max of 20 fec packets
  const constexpr uint32_t first_suffix = 7;
  indexer_.setFirstSuffix(first_suffix);
  indexer_.reset();
  indexer_.enableFec(fec::FECType::RS_K16_N24);
  indexer_.setNFec(8);

  uint32_t index;
  for (uint32_t i = first_suffix; i < 16 + first_suffix; i++) {
    index = indexer_.getNextSuffix();
    EXPECT_FALSE(indexer_.isFec(index));
    EXPECT_EQ(i, index);
  }

  for (uint32_t i = first_suffix + 16; i < 16 + 8 + first_suffix; i++) {
    index = indexer_.getNextSuffix();
    EXPECT_TRUE(indexer_.isFec(index));
    EXPECT_EQ(i, index);
  }
}

}  // namespace protocol
}  // namespace transport
