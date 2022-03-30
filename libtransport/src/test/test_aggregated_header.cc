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
#include <hicn/transport/errors/not_implemented_exception.h>
#include <protocols/rtc/rtc_packet.h>
#include <test/packet_samples.h>

#include <climits>
#include <random>
#include <vector>

namespace transport {

namespace core {

namespace {
// The fixture for testing class Foo.
class AggregatedPktHeaderTest : public ::testing::Test {
 protected:
  AggregatedPktHeaderTest() {
    // You can do set-up work for each test here.
  }

  virtual ~AggregatedPktHeaderTest() {
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
};

}  // namespace

TEST_F(AggregatedPktHeaderTest, Add2Packets8bit) {
  uint8_t buf[1500];
  std::vector<uint8_t> pkt1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
  uint16_t pkt1_len = 14;

  std::vector<uint8_t> pkt2 = {11, 12, 13, 14, 15, 16, 17};
  uint16_t pkt2_len = 7;

  for (uint16_t i = 0; i < 1500; i++) {
    buf[i] = 0;
  }

  // skip protocol::rtc::DATA_HEADER_SIZE that will be the rtc header
  protocol::rtc::AggrPktHeader hdr(buf + protocol::rtc::DATA_HEADER_SIZE,
                                   pkt1_len, 2);
  hdr.addPacketToHeader(0, pkt1_len);
  hdr.addPacketToHeader(1, pkt2_len);
  uint8_t* ptr = hdr.getPayloadAppendPtr();

  // copy packet 1
  for (uint16_t i = 0; i < pkt1_len; i++) {
    *(ptr + i) = pkt1[i];
  }

  // copy packet 2
  for (uint16_t i = 0; i < pkt2_len; i++) {
    *(ptr + i + pkt1_len) = pkt2[i];
  }

  // print
  // for (uint16_t i = 0; i < 40; i++){
  //  std::cout << (int) i << " " << (int) buf[i] << std::endl;
  //}

  uint8_t* pkt_ptr = nullptr;
  uint16_t pkt_len = 0;

  hdr.getPointerToPacket(0, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt1_len);
  for (uint16_t i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt1[i]);
  }

  hdr.getPointerToPacket(1, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt2_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt2[i]);
  }
}

TEST_F(AggregatedPktHeaderTest, Add2Packets8bit255) {
  uint8_t buf[1500];

  std::vector<uint8_t> pkt1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
  uint16_t pkt1_len = 14;

  std::vector<uint8_t> pkt2 = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 20
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 40
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 60
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 80
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 100
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 120
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 140
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 160
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 180
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 200
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 220
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 240
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14};  // 255
  uint16_t pkt2_len = 255;

  for (uint16_t i = 0; i < 1500; i++) {
    buf[i] = 0;
  }

  // skip protocol::rtc::DATA_HEADER_SIZE that will be the rtc header
  protocol::rtc::AggrPktHeader hdr(buf + protocol::rtc::DATA_HEADER_SIZE,
                                   pkt2_len, 2);
  hdr.addPacketToHeader(0, pkt1_len);
  hdr.addPacketToHeader(1, pkt2_len);
  uint8_t* ptr = hdr.getPayloadAppendPtr();

  // copy packet 1
  for (uint16_t i = 0; i < pkt1_len; i++) {
    *(ptr + i) = pkt1[i];
  }

  // copy packet 2
  for (uint16_t i = 0; i < pkt2_len; i++) {
    *(ptr + i + pkt1_len) = pkt2[i];
  }

  uint8_t* pkt_ptr = nullptr;
  uint16_t pkt_len = 0;

  hdr.getPointerToPacket(0, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt1_len);
  for (uint16_t i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt1[i]);
  }

  hdr.getPointerToPacket(1, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt2_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt2[i]);
  }
}

TEST_F(AggregatedPktHeaderTest, Add2Packets8bit256) {
  uint8_t buf[1500];

  std::vector<uint8_t> pkt1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
  uint16_t pkt1_len = 14;

  std::vector<uint8_t> pkt2 = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 20
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 40
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 60
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 80
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 100
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 120
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 140
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 160
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 180
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 200
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 220
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 240
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15};  // 256
  uint16_t pkt2_len = 256;

  for (uint16_t i = 0; i < 1500; i++) {
    buf[i] = 0;
  }

  // skip protocol::rtc::DATA_HEADER_SIZE that will be the rtc header
  protocol::rtc::AggrPktHeader hdr(buf + protocol::rtc::DATA_HEADER_SIZE,
                                   pkt2_len, 2);
  hdr.addPacketToHeader(0, pkt1_len);
  hdr.addPacketToHeader(1, pkt2_len);
  uint8_t* ptr = hdr.getPayloadAppendPtr();

  // copy packet 1
  for (uint16_t i = 0; i < pkt1_len; i++) {
    *(ptr + i) = pkt1[i];
  }

  // copy packet 2
  for (uint16_t i = 0; i < pkt2_len; i++) {
    *(ptr + i + pkt1_len) = pkt2[i];
  }

  uint8_t* pkt_ptr = nullptr;
  uint16_t pkt_len = 0;

  hdr.getPointerToPacket(0, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt1_len);
  for (uint16_t i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt1[i]);
  }

  hdr.getPointerToPacket(1, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt2_len);
  for (uint16_t i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt2[i]);
  }
}

TEST_F(AggregatedPktHeaderTest, Add4Packets8bit) {
  uint8_t buf[1500];

  std::vector<uint8_t> pkt1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
  uint16_t pkt1_len = 14;

  std::vector<uint8_t> pkt2 = {11, 12, 13, 14, 15, 16, 17};
  uint16_t pkt2_len = 7;

  std::vector<uint8_t> pkt3 = {21, 22, 23, 24, 25, 26, 27, 28, 29, 30};
  uint16_t pkt3_len = 10;

  std::vector<uint8_t> pkt4 = {100, 110};
  uint16_t pkt4_len = 2;

  for (uint16_t i = 0; i < 1500; i++) {
    buf[i] = 0;
  }

  // skip protocol::rtc::DATA_HEADER_SIZE that will be the rtc header
  protocol::rtc::AggrPktHeader hdr(buf + protocol::rtc::DATA_HEADER_SIZE,
                                   pkt1_len, 4);
  hdr.addPacketToHeader(0, pkt1_len);
  hdr.addPacketToHeader(1, pkt2_len);
  hdr.addPacketToHeader(2, pkt3_len);
  hdr.addPacketToHeader(3, pkt4_len);
  uint8_t* ptr = hdr.getPayloadAppendPtr();

  // copy packet 1
  for (uint16_t i = 0; i < pkt1_len; i++) {
    *(ptr + i) = pkt1[i];
  }

  // copy packet 2
  for (uint16_t i = 0; i < pkt2_len; i++) {
    *(ptr + i + pkt1_len) = pkt2[i];
  }

  // copy packet 3
  for (uint16_t i = 0; i < pkt3_len; i++) {
    *(ptr + i + pkt1_len + pkt2_len) = pkt3[i];
  }

  // copy packet 2
  for (uint16_t i = 0; i < pkt4_len; i++) {
    *(ptr + i + pkt1_len + pkt2_len + pkt3_len) = pkt4[i];
  }

  uint8_t* pkt_ptr = nullptr;
  uint16_t pkt_len = 0;

  hdr.getPointerToPacket(0, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt1_len);
  for (uint16_t i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt1[i]);
  }

  hdr.getPointerToPacket(1, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt2_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt2[i]);
  }

  hdr.getPointerToPacket(2, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt3_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt3[i]);
  }

  hdr.getPointerToPacket(3, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt4_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt4[i]);
  }
}

TEST_F(AggregatedPktHeaderTest, Add4Packets16bit) {
  uint8_t buf[1500];

  std::vector<uint8_t> pkt1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
  uint16_t pkt1_len = 14;

  std::vector<uint8_t> pkt2 = {11, 12, 13, 14, 15, 16, 17};
  uint16_t pkt2_len = 7;

  std::vector<uint8_t> pkt3 = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 20
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 40
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 60
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 80
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 100
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 120
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 140
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 160
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 180
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 200
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 220
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 240
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19};  // 260
  uint16_t pkt3_len = 260;

  std::vector<uint8_t> pkt4 = {100, 110};
  uint16_t pkt4_len = 2;

  for (uint16_t i = 0; i < 1500; i++) {
    buf[i] = 0;
  }

  // skip protocol::rtc::DATA_HEADER_SIZE that will be the rtc header
  protocol::rtc::AggrPktHeader hdr(buf + protocol::rtc::DATA_HEADER_SIZE,
                                   pkt3_len, 4);
  hdr.addPacketToHeader(0, pkt1_len);
  hdr.addPacketToHeader(1, pkt2_len);
  hdr.addPacketToHeader(2, pkt3_len);
  hdr.addPacketToHeader(3, pkt4_len);
  uint8_t* ptr = hdr.getPayloadAppendPtr();

  // copy packet 1
  for (uint16_t i = 0; i < pkt1_len; i++) {
    *(ptr + i) = pkt1[i];
  }

  // copy packet 2
  for (uint16_t i = 0; i < pkt2_len; i++) {
    *(ptr + i + pkt1_len) = pkt2[i];
  }

  // copy packet 3
  for (uint16_t i = 0; i < pkt3_len; i++) {
    *(ptr + i + pkt1_len + pkt2_len) = pkt3[i];
  }

  // copy packet 2
  for (uint16_t i = 0; i < pkt4_len; i++) {
    *(ptr + i + pkt1_len + pkt2_len + pkt3_len) = pkt4[i];
  }

  uint8_t* pkt_ptr = nullptr;
  uint16_t pkt_len = 0;

  hdr.getPointerToPacket(0, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt1_len);
  for (uint16_t i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt1[i]);
  }

  hdr.getPointerToPacket(1, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt2_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt2[i]);
  }

  hdr.getPointerToPacket(2, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt3_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt3[i]);
  }

  hdr.getPointerToPacket(3, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt4_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt4[i]);
  }
}

TEST_F(AggregatedPktHeaderTest, Defrag4Packets8bit) {
  uint8_t buf[1500];

  std::vector<uint8_t> pkt1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
  uint16_t pkt1_len = 14;

  std::vector<uint8_t> pkt2 = {11, 12, 13, 14, 15, 16, 17};
  uint16_t pkt2_len = 7;

  std::vector<uint8_t> pkt3 = {21, 22, 23, 24, 25, 26, 27, 28, 29, 30};
  uint16_t pkt3_len = 10;

  std::vector<uint8_t> pkt4 = {100, 110};
  uint16_t pkt4_len = 2;

  for (uint16_t i = 0; i < 1500; i++) {
    buf[i] = 0;
  }

  // skip protocol::rtc::DATA_HEADER_SIZE that will be the rtc header
  protocol::rtc::AggrPktHeader hdr(buf + protocol::rtc::DATA_HEADER_SIZE,
                                   pkt1_len, 4);
  hdr.addPacketToHeader(0, pkt1_len);
  hdr.addPacketToHeader(1, pkt2_len);
  hdr.addPacketToHeader(2, pkt3_len);
  hdr.addPacketToHeader(3, pkt4_len);

  uint16_t offset = protocol::rtc::DATA_HEADER_SIZE + 8;  // 8 = aggr hdr

  // copy packet 1
  for (uint16_t i = 0; i < pkt1_len; i++) {
    buf[i + offset] = pkt1[i];
  }
  offset += pkt1_len;

  // copy packet 2
  for (uint16_t i = 0; i < pkt2_len; i++) {
    buf[i + offset] = pkt2[i];
  }
  offset += pkt2_len;

  // copy packet 3
  for (uint16_t i = 0; i < pkt3_len; i++) {
    buf[i + offset] = pkt3[i];
  }
  offset += pkt3_len;

  // copy packet 2
  for (uint16_t i = 0; i < pkt4_len; i++) {
    buf[i + offset] = pkt4[i];
  }

  protocol::rtc::AggrPktHeader hdr2(buf + protocol::rtc::DATA_HEADER_SIZE);

  uint8_t* pkt_ptr = nullptr;
  uint16_t pkt_len = 0;

  uint8_t packet_number = hdr2.getNumberOfPackets();
  EXPECT_EQ(packet_number, 4);

  hdr2.getPointerToPacket(0, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt1_len);
  for (uint16_t i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt1[i]);
  }

  hdr2.getPointerToPacket(1, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt2_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt2[i]);
  }

  hdr2.getPointerToPacket(2, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt3_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt3[i]);
  }

  hdr2.getPointerToPacket(3, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt4_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt4[i]);
  }
}

TEST_F(AggregatedPktHeaderTest, Defrag4Packets16bit) {
  uint8_t buf[1500];

  std::vector<uint8_t> pkt1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
  uint16_t pkt1_len = 14;

  std::vector<uint8_t> pkt2 = {11, 12, 13, 14, 15, 16, 17};
  uint16_t pkt2_len = 7;

  std::vector<uint8_t> pkt3 = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 20
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 40
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 60
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 80
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 100
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 120
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 140
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 160
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 180
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 200
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 220
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19,  // 240
                               0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                               10, 11, 12, 13, 14, 15, 16, 17, 18, 19};  // 260
  uint16_t pkt3_len = 260;

  std::vector<uint8_t> pkt4 = {100, 110};
  uint16_t pkt4_len = 2;

  for (uint16_t i = 0; i < 1500; i++) {
    buf[i] = 0;
  }

  // skip protocol::rtc::DATA_HEADER_SIZE that will be the rtc header
  protocol::rtc::AggrPktHeader hdr(buf + protocol::rtc::DATA_HEADER_SIZE,
                                   pkt3_len, 4);
  hdr.addPacketToHeader(0, pkt1_len);
  hdr.addPacketToHeader(1, pkt2_len);
  hdr.addPacketToHeader(2, pkt3_len);
  hdr.addPacketToHeader(3, pkt4_len);

  uint16_t offset = protocol::rtc::DATA_HEADER_SIZE + 12;  // 12 = aggr hdr

  // copy packet 1
  for (uint16_t i = 0; i < pkt1_len; i++) {
    buf[i + offset] = pkt1[i];
  }
  offset += pkt1_len;

  // copy packet 2
  for (uint16_t i = 0; i < pkt2_len; i++) {
    buf[i + offset] = pkt2[i];
  }
  offset += pkt2_len;

  // copy packet 3
  for (uint16_t i = 0; i < pkt3_len; i++) {
    buf[i + offset] = pkt3[i];
  }
  offset += pkt3_len;

  // copy packet 2
  for (uint16_t i = 0; i < pkt4_len; i++) {
    buf[i + offset] = pkt4[i];
  }

  protocol::rtc::AggrPktHeader hdr2(buf + protocol::rtc::DATA_HEADER_SIZE);

  uint8_t* pkt_ptr = nullptr;
  uint16_t pkt_len = 0;

  uint8_t packet_number = hdr2.getNumberOfPackets();
  EXPECT_EQ(packet_number, 4);

  hdr2.getPointerToPacket(0, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt1_len);
  for (uint16_t i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt1[i]);
  }

  hdr2.getPointerToPacket(1, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt2_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt2[i]);
  }

  hdr2.getPointerToPacket(2, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt3_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt3[i]);
  }

  hdr2.getPointerToPacket(3, &pkt_ptr, &pkt_len);
  EXPECT_EQ(pkt_len, pkt4_len);
  for (int i = 0; i < pkt_len; i++) {
    EXPECT_EQ(*(pkt_ptr + i), pkt4[i]);
  }
}

}  // namespace core
}  // namespace transport
