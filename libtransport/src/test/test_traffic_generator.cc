/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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
#include <hicn/transport/utils/traffic_generator.h>

static constexpr int NUM_PINGS = 10;
static constexpr char PREFIX[] = "b001:1:2:3::";
static constexpr uint32_t FIRST_SUFFIX = 5;

namespace utils {

using transport::IncrSuffixTrafficGenerator;
using transport::RandomTrafficGenerator;

class TrafficGeneratorTest : public ::testing::Test {
 protected:
  TrafficGeneratorTest() {}
  virtual ~TrafficGeneratorTest() {}
};

TEST_F(TrafficGeneratorTest, IncrSuffixGetPrefixAndSuffix) {
  auto traffic_generator_ = std::make_unique<IncrSuffixTrafficGenerator>(
      PREFIX, FIRST_SUFFIX, NUM_PINGS);

  std::string prefix = traffic_generator_->getPrefix();
  EXPECT_EQ(prefix, PREFIX);
  uint32_t suffix = traffic_generator_->getSuffix();
  EXPECT_EQ(suffix, FIRST_SUFFIX);
}

TEST_F(TrafficGeneratorTest, IncrSuffixGetMultipleSuffixes) {
  auto traffic_generator_ = std::make_unique<IncrSuffixTrafficGenerator>(
      PREFIX, FIRST_SUFFIX, NUM_PINGS);

  std::string prefix = traffic_generator_->getPrefix();
  EXPECT_EQ(prefix, PREFIX);
  EXPECT_EQ(prefix, traffic_generator_->getPrefix());

  for (int i = 0; i < NUM_PINGS; i++)
    EXPECT_EQ(traffic_generator_->getSuffix(), FIRST_SUFFIX + i);
}

TEST_F(TrafficGeneratorTest, IncrSuffixReset) {
  auto traffic_generator_ = std::make_unique<IncrSuffixTrafficGenerator>(
      PREFIX, FIRST_SUFFIX, NUM_PINGS);

  for (int i = 0; i < NUM_PINGS; i++) traffic_generator_->getSuffix();

  traffic_generator_->reset();
  EXPECT_EQ(traffic_generator_->getPrefix(), PREFIX);
  EXPECT_EQ(traffic_generator_->getSuffix(), FIRST_SUFFIX);
  EXPECT_EQ(traffic_generator_->getSuffix(), FIRST_SUFFIX + 1);
}

TEST_F(TrafficGeneratorTest, IncrSuffixRequestTooManySuffixes) {
  auto traffic_generator_ = std::make_unique<IncrSuffixTrafficGenerator>(
      PREFIX, FIRST_SUFFIX, NUM_PINGS);

  for (int i = 0; i < NUM_PINGS; i++) traffic_generator_->getSuffix();
  EXPECT_THROW(traffic_generator_->getSuffix(), std::runtime_error);
}

TEST_F(TrafficGeneratorTest, IncrSuffixGetPrefixAndSuffixTogether) {
  auto traffic_generator_ = std::make_unique<IncrSuffixTrafficGenerator>(
      PREFIX, FIRST_SUFFIX, NUM_PINGS);

  auto [prefix, suffix] = traffic_generator_->getPrefixAndSuffix();
  EXPECT_EQ(prefix, PREFIX);
  EXPECT_EQ(suffix, FIRST_SUFFIX);
}

TEST_F(TrafficGeneratorTest, IncrSuffixCheckSentCount) {
  auto traffic_generator_ = std::make_unique<IncrSuffixTrafficGenerator>(
      PREFIX, FIRST_SUFFIX, NUM_PINGS);

  for (int i = 0; i < NUM_PINGS; i++) {
    EXPECT_EQ(traffic_generator_->getSentCount(), i);
    EXPECT_FALSE(traffic_generator_->hasFinished());
    traffic_generator_->getSuffix();
  }
  EXPECT_TRUE(traffic_generator_->hasFinished());
}

TEST_F(TrafficGeneratorTest, RandomGetPrefixAndSuffix) {
  auto traffic_generator_ = std::make_unique<RandomTrafficGenerator>(NUM_PINGS);

  std::string prefix1 = traffic_generator_->getPrefix();
  std::string prefix2 = traffic_generator_->getPrefix();
  EXPECT_NE(prefix1, prefix2);

  uint32_t suffix1 = traffic_generator_->getSuffix();
  uint32_t suffix2 = traffic_generator_->getSuffix();
  EXPECT_NE(suffix1, suffix2);
}

TEST_F(TrafficGeneratorTest, RandomGetPrefixAndSuffixWithNetPrefix) {
  auto traffic_generator_ = std::make_unique<RandomTrafficGenerator>(
      NUM_PINGS, std::string(PREFIX) + "/64");

  for (int i = 0; i < NUM_PINGS; i++)
    EXPECT_THAT(traffic_generator_->getPrefix(),
                testing::StartsWith(std::string(PREFIX)));
}

}  // namespace utils