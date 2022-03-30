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
#include <hicn/transport/utils/rtc_quality_score.h>

#include <climits>
#include <random>
#include <vector>

namespace transport {

namespace protocol {

namespace rtc {

TEST(QualityScoreTest, testQS) {
  RTCQualityScore qs;
  uint8_t score;

  // 0 losses
  score = qs.getQualityScore(0, 0);
  EXPECT_EQ(score, (uint8_t)5);

  score = qs.getQualityScore(98, 0);
  EXPECT_EQ(score, (uint8_t)5);

  score = qs.getQualityScore(188, 0);
  EXPECT_EQ(score, (uint8_t)5);

  score = qs.getQualityScore(398, 0);
  EXPECT_EQ(score, (uint8_t)4);

  score = qs.getQualityScore(400, 0);
  EXPECT_EQ(score, (uint8_t)3);

  score = qs.getQualityScore(598, 0);
  EXPECT_EQ(score, (uint8_t)3);

  score = qs.getQualityScore(600, 0);
  EXPECT_EQ(score, (uint8_t)1);

  score = qs.getQualityScore(700, 0);
  EXPECT_EQ(score, (uint8_t)1);

  score = qs.getQualityScore(50000, 0);
  EXPECT_EQ(score, (uint8_t)1);

  // 0 delay
  score = qs.getQualityScore(0, 2);
  EXPECT_EQ(score, (uint8_t)5);

  score = qs.getQualityScore(0, 9);
  EXPECT_EQ(score, (uint8_t)5);

  score = qs.getQualityScore(0, 29);
  EXPECT_EQ(score, (uint8_t)5);

  score = qs.getQualityScore(0, 30);
  EXPECT_EQ(score, (uint8_t)4);

  score = qs.getQualityScore(0, 39);
  EXPECT_EQ(score, (uint8_t)4);

  score = qs.getQualityScore(0, 40);
  EXPECT_EQ(score, (uint8_t)3);

  score = qs.getQualityScore(0, 50);
  EXPECT_EQ(score, (uint8_t)1);

  score = qs.getQualityScore(0, 5000);
  EXPECT_EQ(score, (uint8_t)1);

  // loss < 10
  score = qs.getQualityScore(0, 3);
  EXPECT_EQ(score, (uint8_t)5);

  score = qs.getQualityScore(98, 9);
  EXPECT_EQ(score, (uint8_t)4);

  score = qs.getQualityScore(100, 9);
  EXPECT_EQ(score, (uint8_t)3);

  score = qs.getQualityScore(398, 5);
  EXPECT_EQ(score, (uint8_t)2);

  score = qs.getQualityScore(400, 5);
  EXPECT_EQ(score, (uint8_t)1);

  score = qs.getQualityScore(4000, 5);
  EXPECT_EQ(score, (uint8_t)1);

  // loss < 20
  score = qs.getQualityScore(0, 10);
  EXPECT_EQ(score, (uint8_t)5);

  score = qs.getQualityScore(30, 10);
  EXPECT_EQ(score, (uint8_t)3);

  score = qs.getQualityScore(198, 15);
  EXPECT_EQ(score, (uint8_t)2);

  score = qs.getQualityScore(200, 19);
  EXPECT_EQ(score, (uint8_t)1);

  score = qs.getQualityScore(300, 10);
  EXPECT_EQ(score, (uint8_t)1);

  // loss < 30

  score = qs.getQualityScore(0, 29);
  EXPECT_EQ(score, (uint8_t)5);

  score = qs.getQualityScore(10, 29);
  EXPECT_EQ(score, (uint8_t)2);

  score = qs.getQualityScore(0, 100);
  EXPECT_EQ(score, (uint8_t)1);
}

}  // namespace rtc
}  // namespace protocol
}  // namespace transport
