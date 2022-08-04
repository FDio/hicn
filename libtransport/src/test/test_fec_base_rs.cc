/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
#include <hicn/transport/core/content_object.h>
#include <hicn/transport/core/global_object_pool.h>
#include <protocols/fec_base.h>
#include <protocols/fec_utils.h>
#include <protocols/rtc/rtc_consts.h>

#include <algorithm>
#include <iostream>
#include <queue>
#include <random>

namespace transport {
namespace protocol {

class PacketFactory {
 public:
  PacketFactory(){};

  ~PacketFactory(){};

  std::shared_ptr<transport::core::ContentObject> createData(
      core::Name &name, uint32_t suffix, uint32_t payload_size,
      uint32_t payload_filler) {
    auto &packet_manager = core::PacketManager<>::getInstance();

    // create payload
    auto buff = packet_manager.getMemBuf();
    buff->append(payload_size);
    std::fill(buff->writableData(), buff->writableTail(), payload_filler);

    // create data packet
    auto data = packet_manager.getPacket<transport::core::ContentObject>(
        HICN_PACKET_FORMAT_IPV6_TCP, 0);
    struct rtc::data_packet_t header;
    header.setTimestamp(1000);
    header.setProductionRate(1);
    data->appendPayload((const uint8_t *)&header, rtc::DATA_HEADER_SIZE);
    data->appendPayload(buff->data(), buff->length());
    data->setName(name.setSuffix(suffix));
    data->setLifetime(500);
    data->setPathLabel(12);

    return data;
  }

  std::shared_ptr<transport::core::ContentObject> createData(
      core::Name &name, uint32_t suffix, fec::buffer payload) {
    auto &packet_manager = core::PacketManager<>::getInstance();

    auto data = packet_manager.getPacket<transport::core::ContentObject>(
        HICN_PACKET_FORMAT_IPV6_TCP, 0);
    struct rtc::data_packet_t header;
    header.setTimestamp(1000);
    header.setProductionRate(1);
    data->appendPayload((const uint8_t *)&header, rtc::DATA_HEADER_SIZE);
    data->appendPayload(payload->data(), payload->length());
    data->setName(name.setSuffix(suffix));
    data->setLifetime(500);
    data->setPathLabel(12);

    return data;
  }
};

class Encoder {
 public:
  Encoder(std::string fec_str) {
    fec_type_ = fec::FECUtils::fecTypeFromString(fec_str.c_str());
    encoder_ = fec::FECUtils::getEncoder(fec_type_, 1);
    encoder_->setFECCallback(
        std::bind(&Encoder::onFecPackets, this, std::placeholders::_1));
    encoder_->setBufferCallback(
        std::bind(&Encoder::getBuffer, this, std::placeholders::_1));
  };

  ~Encoder(){};

  void onFecPackets(fec::BufferArray &packets) {
    for (auto &packet : packets) {
      fec_packets_.push(packet.getBuffer());
    }
  }

  fec::buffer getBuffer(std::size_t size) {
    auto ret = core::PacketManager<>::getInstance()
                   .getPacket<transport::core::ContentObject>(
                       HICN_PACKET_FORMAT_IPV6_TCP, 0);
    ret->updateLength(rtc::DATA_HEADER_SIZE + size);
    ret->append(rtc::DATA_HEADER_SIZE + size);
    ret->trimStart(ret->headerSize() + rtc::DATA_HEADER_SIZE);

    return ret;
  }

  void onPacketProduced(core::ContentObject &content_object, uint32_t offset,
                        uint32_t metadata) {
    encoder_->onPacketProduced(content_object, offset, metadata);
  }

 public:
  std::queue<fec::buffer> fec_packets_;

 private:
  std::unique_ptr<fec::ProducerFEC> encoder_;
  fec::FECType fec_type_;
};

class Decoder {
 public:
  Decoder(std::string fec_str) {
    fec_type_ = fec::FECUtils::fecTypeFromString(fec_str.c_str());
    decoder_ = fec::FECUtils::getDecoder(fec_type_, 1);
    decoder_->setFECCallback(
        std::bind(&Decoder::onFecPackets, this, std::placeholders::_1));
    decoder_->setBufferCallback(fec::FECBase::BufferRequested(0));
  };

  ~Decoder(){};

  void onFecPackets(fec::BufferArray &packets) {
    for (auto &packet : packets) {
      recovered_packets_.push(packet.getBuffer());
    }
  }

  void onPacketReceived(core::ContentObject &content_object, uint32_t offset) {
    decoder_->onDataPacket(content_object, offset);
  }

 public:
  std::queue<fec::buffer> recovered_packets_;

 private:
  std::unique_ptr<fec::ConsumerFEC> decoder_;
  fec::FECType fec_type_;
};

TEST(FECtestRS, RSTestInOrder1) {
  // use RS k = 2 N = 6
  std::string fec_str = "RS_K2_N6";
  Encoder encoder(fec_str);
  Decoder decoder(fec_str);

  PacketFactory pf;

  core::Name name("b001::");

  auto data1 = pf.createData(name, 1, 50, 1);
  const uint8_t *data1_ptr = data1->data();

  auto data2 = pf.createData(name, 2, 45, 2);
  const uint8_t *data2_ptr = data2->data();

  // encoding
  uint32_t metadata = static_cast<uint32_t>(data1->getPayloadType());
  encoder.onPacketProduced(*data1, data1->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);
  encoder.onPacketProduced(*data2, data2->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);

  // create fec packet
  auto data3 = pf.createData(name, 3, encoder.fec_packets_.front());

  // decode in order, data 1 is lost
  decoder.onPacketReceived(*data2, data2->headerSize() + rtc::DATA_HEADER_SIZE);
  decoder.onPacketReceived(*data3, data3->headerSize() + rtc::DATA_HEADER_SIZE);

  // test payload pointers off the original packets
  EXPECT_EQ((const uint8_t *)data1->data(), data1_ptr);
  EXPECT_EQ((const uint8_t *)data2->data(), data2_ptr);

  // check recovered packet
  EXPECT_EQ(decoder.recovered_packets_.size(), (size_t)2);
  auto recovered = pf.createData(name, 1, decoder.recovered_packets_.front());
  bool eq_len = (data1->length() == recovered->length());
  EXPECT_TRUE(eq_len);
  int ret = -1;
  if (eq_len)
    ret = memcmp(data1->data(), recovered->data(), recovered->length());
  EXPECT_EQ(ret, (int)0);
}

TEST(FECtestRS, RSTestInOrder2) {
  // use RS k = 2 N = 6
  std::string fec_str = "RS_K2_N6";
  Encoder encoder(fec_str);
  Decoder decoder(fec_str);

  PacketFactory pf;

  core::Name name("b001::");

  auto data1 = pf.createData(name, 1, 50, 1);
  const uint8_t *data1_ptr = data1->data();

  auto data2 = pf.createData(name, 2, 45, 2);
  const uint8_t *data2_ptr = data2->data();

  // encoding
  uint32_t metadata = static_cast<uint32_t>(data1->getPayloadType());
  encoder.onPacketProduced(*data1, data1->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);
  encoder.onPacketProduced(*data2, data2->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);

  // create fec packet
  auto data3 = pf.createData(name, 3, encoder.fec_packets_.front());

  // decode in order, data 2 is lost
  decoder.onPacketReceived(*data1, data1->headerSize() + rtc::DATA_HEADER_SIZE);
  decoder.onPacketReceived(*data3, data3->headerSize() + rtc::DATA_HEADER_SIZE);

  // test payload pointers off the original packets
  EXPECT_EQ((const uint8_t *)data1->data(), data1_ptr);
  EXPECT_EQ((const uint8_t *)data2->data(), data2_ptr);

  // check recovered packet
  EXPECT_EQ(decoder.recovered_packets_.size(), (size_t)2);
  decoder.recovered_packets_.pop();  // pop data packet 1
  auto recovered = pf.createData(name, 2, decoder.recovered_packets_.front());

  bool eq_len = (data2->length() == recovered->length());
  EXPECT_TRUE(eq_len);
  int ret = -1;
  if (eq_len)
    ret = memcmp(data2->data(), recovered->data(), recovered->length());
  EXPECT_EQ(ret, (int)0);
}

TEST(FECtestRS, RSTestOutOfOrder1) {
  // use RS k = 2 N = 6
  std::string fec_str = "RS_K2_N6";
  Encoder encoder(fec_str);
  Decoder decoder(fec_str);

  PacketFactory pf;

  core::Name name("b001::");

  auto data1 = pf.createData(name, 1, 50, 1);
  const uint8_t *data1_ptr = data1->data();

  auto data2 = pf.createData(name, 2, 45, 2);
  const uint8_t *data2_ptr = data2->data();

  // encoding
  uint32_t metadata = static_cast<uint32_t>(data1->getPayloadType());
  encoder.onPacketProduced(*data1, data1->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);
  encoder.onPacketProduced(*data2, data2->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);

  // create fec packet
  auto data3 = pf.createData(name, 3, encoder.fec_packets_.front());

  // decoding ooo packets. data 1 is lost.
  decoder.onPacketReceived(*data3, data3->headerSize() + rtc::DATA_HEADER_SIZE);
  decoder.onPacketReceived(*data2, data2->headerSize() + rtc::DATA_HEADER_SIZE);

  // test payload pointers off the original packets
  EXPECT_EQ((const uint8_t *)data1->data(), data1_ptr);
  EXPECT_EQ((const uint8_t *)data2->data(), data2_ptr);

  // get recovered packet
  EXPECT_EQ(decoder.recovered_packets_.size(), (size_t)2);
  auto recovered = pf.createData(name, 1, decoder.recovered_packets_.front());
  bool eq_len = (data1->length() == recovered->length());
  EXPECT_TRUE(eq_len);
  int ret = -1;
  if (eq_len)
    ret = memcmp(data1->data(), recovered->data(), recovered->length());
  EXPECT_EQ(ret, (int)0);
}

TEST(FECtestRS, RSTestOutOfOrder2) {
  // use RS k = 2 N = 6
  std::string fec_str = "RS_K2_N6";
  Encoder encoder(fec_str);
  Decoder decoder(fec_str);

  PacketFactory pf;

  core::Name name("b001::");

  auto data1 = pf.createData(name, 1, 50, 1);
  const uint8_t *data1_ptr = data1->data();

  auto data2 = pf.createData(name, 2, 45, 2);
  const uint8_t *data2_ptr = data2->data();

  // encoding
  uint32_t metadata = static_cast<uint32_t>(data1->getPayloadType());
  encoder.onPacketProduced(*data1, data1->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);
  encoder.onPacketProduced(*data2, data2->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);

  // create fec packet
  auto data3 = pf.createData(name, 3, encoder.fec_packets_.front());

  // decoding ooo packets. data 2 is lost.
  decoder.onPacketReceived(*data3, data3->headerSize() + rtc::DATA_HEADER_SIZE);
  decoder.onPacketReceived(*data1, data2->headerSize() + rtc::DATA_HEADER_SIZE);

  // test payload pointers off the original packets
  EXPECT_EQ((const uint8_t *)data1->data(), data1_ptr);
  EXPECT_EQ((const uint8_t *)data2->data(), data2_ptr);

  // get recovered packet
  EXPECT_EQ(decoder.recovered_packets_.size(), (size_t)2);
  decoder.recovered_packets_.pop();  // pop data packet 1

  auto recovered = pf.createData(name, 2, decoder.recovered_packets_.front());
  bool eq_len = (data2->length() == recovered->length());
  EXPECT_TRUE(eq_len);
  int ret = -1;
  if (eq_len)
    ret = memcmp(data2->data(), recovered->data(), recovered->length());
  EXPECT_EQ(ret, (int)0);
}

TEST(FECtestRS, RSTestLargerBlocks) {
  // use RS k = 4 N = 7
  std::string fec_str = "RS_K4_N7";
  Encoder encoder(fec_str);
  Decoder decoder(fec_str);

  PacketFactory pf;

  core::Name name("b001::");

  auto data1 = pf.createData(name, 1, 50, 1);
  const uint8_t *data1_ptr = data1->data();

  auto data2 = pf.createData(name, 2, 45, 2);
  const uint8_t *data2_ptr = data2->data();

  auto data3 = pf.createData(name, 3, 12, 3);
  const uint8_t *data3_ptr = data3->data();

  auto data4 = pf.createData(name, 4, 20, 4);
  const uint8_t *data4_ptr = data4->data();

  // encoding
  uint32_t metadata = static_cast<uint32_t>(data1->getPayloadType());
  encoder.onPacketProduced(*data1, data1->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);
  encoder.onPacketProduced(*data2, data2->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);
  encoder.onPacketProduced(*data3, data3->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);
  encoder.onPacketProduced(*data4, data4->headerSize() + rtc::DATA_HEADER_SIZE,
                           metadata);

  // create fec packet
  auto data5 = pf.createData(name, 5, encoder.fec_packets_.front());
  encoder.fec_packets_.pop();  // pop 5
  encoder.fec_packets_.pop();  // pop 6
  auto data7 = pf.createData(name, 7, encoder.fec_packets_.front());

  // decoding packets: lost data 3 and data 4
  decoder.onPacketReceived(*data2, data2->headerSize() + rtc::DATA_HEADER_SIZE);
  decoder.onPacketReceived(*data7, data7->headerSize() + rtc::DATA_HEADER_SIZE);
  decoder.onPacketReceived(*data1, data1->headerSize() + rtc::DATA_HEADER_SIZE);
  decoder.onPacketReceived(*data5, data5->headerSize() + rtc::DATA_HEADER_SIZE);

  // test payload pointers off the original packets
  EXPECT_EQ((const uint8_t *)data1->data(), data1_ptr);
  EXPECT_EQ((const uint8_t *)data2->data(), data2_ptr);
  EXPECT_EQ((const uint8_t *)data3->data(), data3_ptr);
  EXPECT_EQ((const uint8_t *)data4->data(), data4_ptr);

  // get recovered packet
  EXPECT_EQ(decoder.recovered_packets_.size(), (size_t)4);
  decoder.recovered_packets_.pop();  // pop data 1
  decoder.recovered_packets_.pop();  // pop data 2
  auto recovered3 = pf.createData(name, 3, decoder.recovered_packets_.front());
  decoder.recovered_packets_.pop();  // pop data 3
  auto recovered4 = pf.createData(name, 4, decoder.recovered_packets_.front());

  bool eq_len = (data3->length() == recovered3->length());
  EXPECT_TRUE(eq_len);
  int ret = -1;
  if (eq_len)
    ret = memcmp(data3->data(), recovered3->data(), recovered3->length());
  EXPECT_EQ(ret, (int)0);

  eq_len = (data4->length() == recovered4->length());
  EXPECT_TRUE(eq_len);
  ret = -1;
  if (eq_len)
    ret = memcmp(data4->data(), recovered4->data(), recovered4->length());
  EXPECT_EQ(ret, (int)0);
}

}  // namespace protocol
}  // namespace transport
