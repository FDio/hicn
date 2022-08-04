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
#include <hicn/transport/core/packet.h>
#include <hicn/transport/errors/not_implemented_exception.h>
#include <hicn/transport/utils/chrono_typedefs.h>
#include <test/packet_samples.h>

#include <climits>
#include <random>
#include <vector>

#include "../../lib/src/protocol.h"

namespace transport {

namespace core {

/**
 * Since packet is an abstract class, we derive a concrete class to be used for
 * the test.
 */
class PacketForTest : public Packet {
 public:
  template <typename... Args>
  PacketForTest(Args &&...args) : Packet(std::forward<Args>(args)...) {}

  virtual ~PacketForTest() {}

  const Name &getName() const override {
    throw errors::NotImplementedException();
  }

  Name &getWritableName() override { throw errors::NotImplementedException(); }

  void setName(const Name &name) override {
    throw errors::NotImplementedException();
  }

  void setLifetime(uint32_t lifetime) override {
    throw errors::NotImplementedException();
  }

  uint32_t getLifetime() const override {
    throw errors::NotImplementedException();
  }

  void setLocator(const hicn_ip_address_t &locator) override {
    throw errors::NotImplementedException();
  }

  void resetForHash() override { throw errors::NotImplementedException(); }

  hicn_ip_address_t getLocator() const override {
    throw errors::NotImplementedException();
  }
};

namespace {
// The fixture for testing class Foo.
class PacketTest : public ::testing::Test {
 protected:
  PacketTest()
      : name_("b001::123|321"),
        packet(Packet::COPY_BUFFER,
               &raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32][0],
               raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size()) {
    // You can do set-up work for each test here.
  }

  virtual ~PacketTest() {
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

  Name name_;

  PacketForTest packet;

  static std::map<uint32_t, std::vector<uint8_t>> raw_packets_;

  std::vector<uint8_t> payload = {
      0x11, 0x11, 0x01, 0x00, 0xb0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad  // , 0x00, 0x00,
                                                            // 0x00, 0x45, 0xa3,
                                                            // 0xd1, 0xf2, 0x2b,
                                                            // 0x94, 0x41, 0x22,
                                                            // 0xc9, 0x00, 0x00,
                                                            // 0x00, 0x44, 0xa3,
                                                            // 0xd1, 0xf2, 0x2b,
                                                            // 0x94, 0x41, 0x22,
                                                            // 0xc8
  };
};

std::map<uint32_t, std::vector<uint8_t>> PacketTest::raw_packets_ = {
    {HICN_PACKET_FORMAT_IPV6_TCP.as_u32,

     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV6_HEADER(TCP_PROTO, 20 + PAYLOAD_SIZE),
      // TCP src=0x1234 dst=0x4321, seq=0x0001
      TCP_HEADER(0x00),
      // Payload
      PAYLOAD}},

    {HICN_PACKET_FORMAT_IPV4_TCP.as_u32,
     {// IPv4 src=3.13.127.8, dst=192.168.1.92
      IPV4_HEADER(TCP_PROTO, 20 + PAYLOAD_SIZE),
      // TCP src=0x1234 dst=0x4321, seq=0x0001
      TCP_HEADER(0x00),
      // Other
      PAYLOAD}},

    {HICN_PACKET_FORMAT_IPV4_ICMP.as_u32,
     {// IPv4 src=3.13.127.8, dst=192.168.1.92
      IPV4_HEADER(ICMP_PROTO, 64),
      // ICMP echo request
      ICMP_ECHO_REQUEST}},

    {HICN_PACKET_FORMAT_IPV6_ICMP.as_u32,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV6_HEADER(ICMP6_PROTO, 60),
      // ICMP6 echo request
      ICMP6_ECHO_REQUEST}},

    {HICN_PACKET_FORMAT_IPV6_TCP_AH.as_u32,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV6_HEADER(TCP_PROTO, 20 + 44 + 128),
      // ICMP6 echo request
      TCP_HEADER(0x18),
      // hICN AH header
      AH_HEADER, SIGNATURE}},

    {HICN_PACKET_FORMAT_IPV4_TCP_AH.as_u32,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV4_HEADER(TCP_PROTO, 20 + 44 + 128),
      // ICMP6 echo request
      TCP_HEADER(0x18),
      // hICN AH header
      AH_HEADER, SIGNATURE}},

    // XXX No flag defined in ICMP header to signal AH header.
    {HICN_PACKET_FORMAT_IPV4_ICMP_AH.as_u32,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV4_HEADER(ICMP_PROTO, 64 + 44),
      // ICMP6 echo request
      ICMP_ECHO_REQUEST,
      // hICN AH header
      AH_HEADER, SIGNATURE}},

    {HICN_PACKET_FORMAT_IPV6_ICMP_AH.as_u32,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV6_HEADER(ICMP6_PROTO, 60 + 44),
      // ICMP6 echo request
      ICMP6_ECHO_REQUEST,
      // hICN AH header
      AH_HEADER, SIGNATURE}},

};

void testFormatConstructor(Packet::Format format = HICN_PACKET_FORMAT_NONE) {
  try {
    PacketForTest packet(HICN_PACKET_TYPE_INTEREST, format);
  } catch (...) {
    char buf[MAXSZ_HICN_PACKET_FORMAT];
    int rc = hicn_packet_format_snprintf(buf, MAXSZ_HICN_PACKET_FORMAT, format);
    if (rc < 0 || rc >= MAXSZ_HICN_PACKET_FORMAT)
      snprintf(buf, MAXSZ_HICN_PACKET_FORMAT, "%s", "(error");
    FAIL() << "ERROR: Unexpected exception thrown for " << buf;
  }
}

void testFormatAndAdditionalHeaderConstructor(Packet::Format format,
                                              std::size_t additional_header) {
  PacketForTest packet(HICN_PACKET_TYPE_INTEREST, format, additional_header);
  // Packet length should be the one of the normal header + the
  // additional_header

  EXPECT_EQ(packet.headerSize(),
            Packet::getHeaderSizeFromFormat(format) + additional_header);
}

void testRawBufferConstructor(std::vector<uint8_t> packet,
                              Packet::Format format) {
  try {
    // Try to construct packet from correct buffer
    PacketForTest p(Packet::WRAP_BUFFER, &packet[0], packet.size(),
                    packet.size());

    // Check format is expected one.
    EXPECT_EQ(p.getFormat().as_u32, format.as_u32);

    // // Try the same using a MemBuf
    // auto buf = utils::MemBuf::wrapBuffer(&packet[0], packet.size());
    // buf->append(packet.size());
    // PacketForTest p2(std::move(buf));

    // EXPECT_EQ(p2.getFormat(), format);
  } catch (...) {
    FAIL() << "ERROR: Unexpected exception thrown";
  }

  try {
    // Try to construct packet from wrong buffer

    // Modify next header to 0
    /* ipv6 */
    packet[6] = 0x00;
    /* ipv4 */
    packet[9] = 0x00;
    PacketForTest p(Packet::WRAP_BUFFER, &packet[0], packet.size(),
                    packet.size());

    // Format should fallback to HICN_PACKET_FORMAT_NONE
    EXPECT_EQ(p.getFormat().as_u32, HICN_PACKET_FORMAT_NONE.as_u32);
  } catch (errors::MalformedPacketException &exc) {
    // Ok right exception
  } catch (...) {
    FAIL() << "ERROR: Unexpected exception thrown.";
  }
}

void getHeaderSizeFromBuffer(std::vector<uint8_t> &packet,
                             std::size_t expected) {
  auto header_size =
      PacketForTest::getHeaderSizeFromBuffer(&packet[0], packet.size());
  EXPECT_EQ(header_size, expected);
}

void getHeaderSizeFromFormat(Packet::Format format, std::size_t expected) {
  auto header_size = PacketForTest::getHeaderSizeFromFormat(format);
  EXPECT_EQ(header_size, expected);
}

void getPayloadSizeFromBuffer(std::vector<uint8_t> &packet,
                              std::size_t expected) {
  auto payload_size =
      PacketForTest::getPayloadSizeFromBuffer(&packet[0], packet.size());
  EXPECT_EQ(payload_size, expected);
}

void getFormatFromBuffer(Packet::Format expected,
                         std::vector<uint8_t> &packet) {
  auto format = PacketForTest::getFormatFromBuffer(&packet[0], packet.size());
  EXPECT_EQ(format.as_u32, expected.as_u32);
}

void getHeaderSize(std::size_t expected, const PacketForTest &packet) {
  auto size = packet.headerSize();
  EXPECT_EQ(size, expected);
}

void testGetFormat(Packet::Format expected, const Packet &packet) {
  auto format = packet.getFormat();
  EXPECT_EQ(format.as_u32, expected.as_u32);
}

}  // namespace

TEST_F(PacketTest, ConstructorWithFormat) {
  testFormatConstructor(HICN_PACKET_FORMAT_IPV4_TCP);
  testFormatConstructor(HICN_PACKET_FORMAT_IPV6_TCP);
  testFormatConstructor(HICN_PACKET_FORMAT_IPV4_ICMP);
  testFormatConstructor(HICN_PACKET_FORMAT_IPV6_ICMP);
  testFormatConstructor(HICN_PACKET_FORMAT_IPV4_TCP_AH);
  testFormatConstructor(HICN_PACKET_FORMAT_IPV6_TCP_AH);
  testFormatConstructor(HICN_PACKET_FORMAT_IPV4_ICMP_AH);
  testFormatConstructor(HICN_PACKET_FORMAT_IPV6_ICMP_AH);
}

TEST_F(PacketTest, ConstructorWithFormatAndAdditionalHeader) {
  testFormatAndAdditionalHeaderConstructor(HICN_PACKET_FORMAT_IPV4_TCP, 123);
  testFormatAndAdditionalHeaderConstructor(HICN_PACKET_FORMAT_IPV6_TCP, 360);
  testFormatAndAdditionalHeaderConstructor(HICN_PACKET_FORMAT_IPV4_ICMP, 21);
  testFormatAndAdditionalHeaderConstructor(HICN_PACKET_FORMAT_IPV6_ICMP, 444);
  testFormatAndAdditionalHeaderConstructor(HICN_PACKET_FORMAT_IPV4_TCP_AH, 555);
  testFormatAndAdditionalHeaderConstructor(HICN_PACKET_FORMAT_IPV6_TCP_AH, 321);
  testFormatAndAdditionalHeaderConstructor(HICN_PACKET_FORMAT_IPV4_ICMP_AH,
                                           123);
  testFormatAndAdditionalHeaderConstructor(HICN_PACKET_FORMAT_IPV6_ICMP_AH, 44);
}

TEST_F(PacketTest, ConstructorWithNew) {
  auto &_packet = raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32];
  auto packet_ptr = new PacketForTest(Packet::WRAP_BUFFER, &_packet[0],
                                      _packet.size(), _packet.size());
  delete packet_ptr;
}

TEST_F(PacketTest, ConstructorWithRawBufferInet6Tcp) {
  auto format = HICN_PACKET_FORMAT_IPV6_TCP;
  testRawBufferConstructor(raw_packets_[format.as_u32], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInetTcp) {
  auto format = HICN_PACKET_FORMAT_IPV4_TCP;
  testRawBufferConstructor(raw_packets_[format.as_u32], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInetIcmp) {
  auto format = HICN_PACKET_FORMAT_IPV4_ICMP;
  testRawBufferConstructor(raw_packets_[format.as_u32], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInet6Icmp) {
  auto format = HICN_PACKET_FORMAT_IPV6_ICMP;
  testRawBufferConstructor(raw_packets_[format.as_u32], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInet6TcpAh) {
  auto format = HICN_PACKET_FORMAT_IPV6_TCP_AH;
  testRawBufferConstructor(raw_packets_[format.as_u32], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInetTcpAh) {
  auto format = HICN_PACKET_FORMAT_IPV4_TCP_AH;
  testRawBufferConstructor(raw_packets_[format.as_u32], format);
}

TEST_F(PacketTest, MoveConstructor) {
  PacketForTest p0(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP);
  PacketForTest p1(std::move(p0));
  EXPECT_EQ(p0.getFormat().as_u32, HICN_PACKET_FORMAT_NONE.as_u32);
  EXPECT_EQ(p1.getFormat().as_u32, HICN_PACKET_FORMAT_IPV6_TCP.as_u32);
}

TEST_F(PacketTest, TestGetHeaderSizeFromBuffer) {
  getHeaderSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32],
                          IPV6_HDRLEN + TCP_HDRLEN);
  getHeaderSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP.as_u32],
                          IPV4_HDRLEN + TCP_HDRLEN);
  getHeaderSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32],
                          IPV6_HDRLEN + 4);
  getHeaderSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV4_ICMP.as_u32],
                          IPV4_HDRLEN + 4);
  getHeaderSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP_AH.as_u32],
                          IPV6_HDRLEN + TCP_HDRLEN + AH_HDRLEN + 128);
  getHeaderSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP_AH.as_u32],
                          IPV4_HDRLEN + TCP_HDRLEN + AH_HDRLEN + 128);
}

TEST_F(PacketTest, TestGetHeaderSizeFromFormat) {
  getHeaderSizeFromFormat(HICN_PACKET_FORMAT_IPV6_TCP,
                          IPV6_HDRLEN + TCP_HDRLEN);
  getHeaderSizeFromFormat(HICN_PACKET_FORMAT_IPV4_TCP,
                          IPV4_HDRLEN + TCP_HDRLEN);
  getHeaderSizeFromFormat(HICN_PACKET_FORMAT_IPV6_ICMP, IPV6_HDRLEN + 4);
  getHeaderSizeFromFormat(HICN_PACKET_FORMAT_IPV4_ICMP, IPV4_HDRLEN + 4);
  getHeaderSizeFromFormat(HICN_PACKET_FORMAT_IPV6_TCP_AH,
                          IPV6_HDRLEN + TCP_HDRLEN + AH_HDRLEN);
  getHeaderSizeFromFormat(HICN_PACKET_FORMAT_IPV4_TCP_AH,
                          IPV4_HDRLEN + TCP_HDRLEN + AH_HDRLEN);
}

TEST_F(PacketTest, TestGetPayloadSizeFromBuffer) {
  getPayloadSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32],
                           12);
  getPayloadSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP.as_u32],
                           12);
  getPayloadSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32],
                           56);
  getPayloadSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV4_ICMP.as_u32],
                           60);
  getPayloadSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP_AH.as_u32],
                           0);
  getPayloadSizeFromBuffer(raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP_AH.as_u32],
                           0);
}

#if 0
TEST_F(PacketTest, TestIsInterest) {
  auto ret = PacketForTest::isInterest(&raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32][0]);

  EXPECT_TRUE(ret);
}
#endif

TEST_F(PacketTest, TestGetFormatFromBuffer) {
  getFormatFromBuffer(HICN_PACKET_FORMAT_IPV6_TCP,
                      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32]);
  getFormatFromBuffer(HICN_PACKET_FORMAT_IPV4_TCP,
                      raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP.as_u32]);
  getFormatFromBuffer(HICN_PACKET_FORMAT_IPV6_ICMP,
                      raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32]);
  getFormatFromBuffer(HICN_PACKET_FORMAT_IPV4_ICMP,
                      raw_packets_[HICN_PACKET_FORMAT_IPV4_ICMP.as_u32]);
  getFormatFromBuffer(HICN_PACKET_FORMAT_IPV6_TCP_AH,
                      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP_AH.as_u32]);
  getFormatFromBuffer(HICN_PACKET_FORMAT_IPV4_TCP_AH,
                      raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP_AH.as_u32]);
}

// TEST_F(PacketTest, TestReplace) {
//   PacketForTest packet(Packet::WRAP_BUFFER,
//   &raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32][0],
//                        raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size());

//   // Replace current packet with another one
//   packet.replace(&raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP.as_u32][0],
//                  raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP.as_u32].size());

//   // Check new format
//   ASSERT_EQ(packet.getFormat(), HICN_PACKET_FORMAT_IPV4_TCP);
// }

TEST_F(PacketTest, TestPayloadSize) {
  // Check payload size of existing packet
  auto &_packet = raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32];
  PacketForTest packet(Packet::WRAP_BUFFER, &_packet[0], _packet.size(),
                       _packet.size());

  EXPECT_EQ(packet.payloadSize(), std::size_t(PAYLOAD_SIZE));

  // Check for dynamic generated packet
  std::string payload0(1024, 'X');

  // Create the packet
  PacketForTest packet2(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP);

  // Payload size should now be zero
  EXPECT_EQ(packet2.payloadSize(), std::size_t(0));

  // Append payload 1 time
  packet2.appendPayload((const uint8_t *)payload0.c_str(), payload0.size());

  // size should now be 1024
  EXPECT_EQ(packet2.payloadSize(), std::size_t(1024));

  // Append second payload
  std::string payload1(1024, 'X');
  packet2.appendPayload((const uint8_t *)payload1.c_str(), payload1.size());

  // Check size is 2048
  EXPECT_EQ(packet2.payloadSize(), std::size_t(2048));

  // Append Membuf
  packet2.appendPayload(utils::MemBuf::copyBuffer(
      (const uint8_t *)payload1.c_str(), payload1.size()));

  // Check size is 3072
  EXPECT_EQ(packet2.payloadSize(), std::size_t(3072));
}

TEST_F(PacketTest, TestHeaderSize) {
  getHeaderSize(
      IPV6_HDRLEN + TCP_HDRLEN,
      PacketForTest(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP));
  getHeaderSize(
      IPV4_HDRLEN + TCP_HDRLEN,
      PacketForTest(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV4_TCP));
  getHeaderSize(
      IPV6_HDRLEN + ICMP_HDRLEN,
      PacketForTest(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_ICMP));
  getHeaderSize(
      IPV4_HDRLEN + ICMP_HDRLEN,
      PacketForTest(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV4_ICMP));
  getHeaderSize(
      IPV6_HDRLEN + TCP_HDRLEN + AH_HDRLEN,
      PacketForTest(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP_AH));
  getHeaderSize(
      IPV4_HDRLEN + TCP_HDRLEN + AH_HDRLEN,
      PacketForTest(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV4_TCP_AH));
}

TEST_F(PacketTest, TestMemBufReference) {
  // Create packet
  auto &_packet = raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32];

  // Packet was not created as a shared_ptr. If we try to get a membuf shared
  // ptr we should get an exception.
  // TODO test with c++ 17
  // try {
  //   PacketForTest packet(&_packet[0], _packet.size());
  //   auto membuf_ref = packet.acquireMemBufReference();
  //   FAIL() << "The acquireMemBufReference() call should have throwed an "
  //             "exception!";
  // } catch (const std::bad_weak_ptr &e) {
  //   // Ok
  // } catch (...) {
  //   FAIL() << "Not expected exception.";
  // }

  auto packet_ptr = std::make_shared<PacketForTest>(
      Packet::WRAP_BUFFER, &_packet[0], _packet.size(), _packet.size());
  PacketForTest &packet = *packet_ptr;

  // Acquire a reference to the membuf
  auto membuf_ref = packet.acquireMemBufReference();

  // Check refcount. It should be 2
  EXPECT_EQ(membuf_ref.use_count(), 2);

  // Now increment membuf references
  Packet::MemBufPtr membuf = packet.acquireMemBufReference();

  // Now reference count should be 2
  EXPECT_EQ(membuf_ref.use_count(), 3);

  // Copy again
  Packet::MemBufPtr membuf2 = membuf;

  // Now reference count should be 3
  EXPECT_EQ(membuf_ref.use_count(), 4);
}

TEST_F(PacketTest, TestReset) {
  // Check everything is ok
  EXPECT_EQ(packet.getFormat().as_u32, HICN_PACKET_FORMAT_IPV6_TCP.as_u32);
  EXPECT_EQ(packet.length(),
            raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size());
  EXPECT_EQ(packet.headerSize(), IPV6_HDRLEN + TCP_HDRLEN);
  EXPECT_EQ(packet.payloadSize(), packet.length() - packet.headerSize());

  // Reset the packet
  packet.reset();

  // Rerun test
  EXPECT_EQ(packet.getFormat().as_u32, HICN_PACKET_FORMAT_NONE.as_u32);
  EXPECT_EQ(packet.length(), std::size_t(0));
  EXPECT_EQ(packet.headerSize(), std::size_t(0));
  EXPECT_EQ(packet.payloadSize(), std::size_t(0));
}

TEST_F(PacketTest, TestAppendPayload) {
  // Append payload with raw buffer
  uint8_t raw_buffer[2048];
  auto original_payload_length = packet.payloadSize();
  packet.appendPayload(raw_buffer, 1024);

  EXPECT_EQ(original_payload_length + 1024, packet.payloadSize());

  for (int i = 0; i < 10; i++) {
    // Append other payload 10 times
    packet.appendPayload(raw_buffer, 1024);
    EXPECT_EQ(original_payload_length + 1024 + (1024) * (i + 1),
              packet.payloadSize());
  }

  // Append payload using membuf
  packet.appendPayload(utils::MemBuf::copyBuffer(raw_buffer, 2048));
  EXPECT_EQ(original_payload_length + 1024 + 1024 * 10 + 2048,
            packet.payloadSize());

  // Check the underlying MemBuf length is the expected one
  utils::MemBuf *current = &packet;
  size_t total = 0;
  do {
    total += current->length();
    current = current->next();
  } while (current != &packet);

  EXPECT_EQ(total, packet.headerSize() + packet.payloadSize());

  // LEt's try now to reset this packet
  packet.reset();

  // There should be no more bufferls left in the chain
  EXPECT_EQ(&packet, packet.next());
  EXPECT_EQ(packet.getFormat().as_u32, HICN_PACKET_FORMAT_NONE.as_u32);
  EXPECT_EQ(packet.length(), std::size_t(0));
  EXPECT_EQ(packet.headerSize(), std::size_t(0));
  EXPECT_EQ(packet.payloadSize(), std::size_t(0));
}

TEST_F(PacketTest, GetPayload) {
  // Append payload with raw buffer
  uint8_t raw_buffer[2048];
  memset(raw_buffer, 0, sizeof(raw_buffer));
  auto original_payload_length = packet.payloadSize();
  packet.appendPayload(raw_buffer, 2048);

  // Get payload
  auto payload = packet.getPayload();
  // Check payload length is correct
  utils::MemBuf *current = payload.get();
  size_t total = 0;
  do {
    total += current->length();
    current = current->next();
  } while (current != payload.get());

  ASSERT_EQ(total, packet.payloadSize());

  // Linearize the payload
  payload->gather(total);

  // Check memory correspond
  payload->trimStart(original_payload_length);
  auto ret = memcmp(raw_buffer, payload->data(), 2048);
  EXPECT_EQ(ret, 0);
}

TEST_F(PacketTest, UpdateLength) {
  auto original_payload_size = packet.payloadSize();

  // Add some fake payload without using the API
  packet.append(200);

  // payloadSize does not know about the new payload, yet
  EXPECT_EQ(packet.payloadSize(), original_payload_size);

  // Let's now update the packet length
  packet.updateLength();

  // Now payloadSize knows
  EXPECT_EQ(packet.payloadSize(), std::size_t(original_payload_size + 200));

  // We may also update the length without adding real content. This is only
  // written in the packet header.
  packet.updateLength(128);
  EXPECT_EQ(packet.payloadSize(),
            std::size_t(original_payload_size + 200 + 128));
}

TEST_F(PacketTest, SetGetPayloadType) {
  auto payload_type = packet.getPayloadType();

  // It should be normal content object by default
  EXPECT_EQ(payload_type, PayloadType::DATA);

  // Set it to be manifest
  packet.setPayloadType(PayloadType::MANIFEST);

  // Check it is manifest
  payload_type = packet.getPayloadType();

  EXPECT_EQ(payload_type, PayloadType::MANIFEST);
}

TEST_F(PacketTest, GetFormat) {
  {
    PacketForTest p0(Packet::WRAP_BUFFER,
                     &raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP.as_u32][0],
                     raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP.as_u32].size(),
                     raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP.as_u32].size());
    testGetFormat(HICN_PACKET_FORMAT_IPV4_TCP, p0);

    PacketForTest p1(Packet::WRAP_BUFFER,
                     &raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32][0],
                     raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size(),
                     raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size());
    testGetFormat(HICN_PACKET_FORMAT_IPV6_TCP, p1);

    PacketForTest p2(Packet::WRAP_BUFFER,
                     &raw_packets_[HICN_PACKET_FORMAT_IPV4_ICMP.as_u32][0],
                     raw_packets_[HICN_PACKET_FORMAT_IPV4_ICMP.as_u32].size(),
                     raw_packets_[HICN_PACKET_FORMAT_IPV4_ICMP.as_u32].size());
    testGetFormat(HICN_PACKET_FORMAT_IPV4_ICMP, p2);

    PacketForTest p3(Packet::WRAP_BUFFER,
                     &raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32][0],
                     raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32].size(),
                     raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32].size());
    testGetFormat(HICN_PACKET_FORMAT_IPV6_ICMP, p3);

    PacketForTest p4(
        Packet::WRAP_BUFFER,
        &raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP_AH.as_u32][0],
        raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP_AH.as_u32].size(),
        raw_packets_[HICN_PACKET_FORMAT_IPV4_TCP_AH.as_u32].size());
    testGetFormat(HICN_PACKET_FORMAT_IPV4_TCP_AH, p4);

    PacketForTest p5(
        Packet::WRAP_BUFFER,
        &raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP_AH.as_u32][0],
        raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP_AH.as_u32].size(),
        raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP_AH.as_u32].size());
    testGetFormat(HICN_PACKET_FORMAT_IPV6_TCP_AH, p5);
  }

  // Let's try now creating empty packets
  {
    PacketForTest p0(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV4_TCP);
    testGetFormat(HICN_PACKET_FORMAT_IPV4_TCP, p0);

    PacketForTest p1(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP);
    testGetFormat(HICN_PACKET_FORMAT_IPV6_TCP, p1);

    PacketForTest p2(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV4_ICMP);
    testGetFormat(HICN_PACKET_FORMAT_IPV4_ICMP, p2);

    PacketForTest p3(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_ICMP);
    testGetFormat(HICN_PACKET_FORMAT_IPV6_ICMP, p3);

    PacketForTest p4(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV4_TCP_AH);
    testGetFormat(HICN_PACKET_FORMAT_IPV4_TCP_AH, p4);

    PacketForTest p5(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP_AH);
    testGetFormat(HICN_PACKET_FORMAT_IPV6_TCP_AH, p5);
  }
}

TEST_F(PacketTest, SetGetTestSignatureTimestamp) {
  // Let's try to set the signature timestamp in a packet without AH header. We
  // expect an exception.
  using namespace std::chrono;
  uint64_t now = utils::SteadyTime::nowMs().count();

  try {
    packet.setSignatureTimestamp(now);
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  // Same fot get method
  try {
    auto t = packet.getSignatureTimestamp();
    // Let's make compiler happy
    (void)t;
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  // Now let's construct a AH packet, with no additional space for signature
  PacketForTest p(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP_AH);
  p.setSignatureTimestamp(now);
  uint64_t now_get = p.getSignatureTimestamp();

  // Check we got the right value
  EXPECT_EQ(now_get, now);
}

TEST_F(PacketTest, TestSetGetValidationAlgorithm) {
  // Let's try to set the validation algorithm in a packet without AH header. We
  // expect an exception.

  try {
    packet.setValidationAlgorithm(auth::CryptoSuite::RSA_SHA256);
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  // Same fot get method
  try {
    auto v = packet.getSignatureTimestamp();
    // Let's make compiler happy
    (void)v;
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  // Now let's construct a AH packet, with no additional space for signature
  PacketForTest p(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP_AH);
  p.setValidationAlgorithm(auth::CryptoSuite::RSA_SHA256);
  auto v_get = p.getValidationAlgorithm();

  // Check we got the right value
  EXPECT_EQ(v_get, auth::CryptoSuite::RSA_SHA256);
}

TEST_F(PacketTest, TestSetGetKeyId) {
  uint8_t key[32];
  memset(key, 0, sizeof(key));
  auth::KeyId key_id = std::make_pair(key, sizeof(key));

  try {
    packet.setKeyId(key_id);
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  // Same for get method
  try {
    auto k = packet.getKeyId();
    // Let's make compiler happy
    (void)k;
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  // Now let's construct a AH packet, with no additional space for signature
  PacketForTest p(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP_AH);
  p.setKeyId(key_id);
  auto p_get = p.getKeyId();

  // Check we got the right value
  EXPECT_EQ(p_get.second, key_id.second);

  auto ret = memcmp(p_get.first, key_id.first, p_get.second);
  EXPECT_EQ(ret, 0);
}

TEST_F(PacketTest, DISABLED_TestChecksum) {
  // Checksum should be wrong
  bool integrity = packet.checkIntegrity();
  EXPECT_FALSE(integrity);

  // Let's fix it
  packet.setChecksum();

  // Check again
  integrity = packet.checkIntegrity();
  EXPECT_TRUE(integrity);

  // Check with AH header and 300 bytes signature
  PacketForTest p(HICN_PACKET_TYPE_INTEREST, HICN_PACKET_FORMAT_IPV6_TCP_AH,
                  300);
  std::string payload(5000, 'X');
  p.appendPayload((const uint8_t *)payload.c_str(), payload.size() / 2);
  p.appendPayload((const uint8_t *)(payload.c_str() + payload.size() / 2),
                  payload.size() / 2);

  p.setChecksum();
  integrity = p.checkIntegrity();
  EXPECT_TRUE(integrity);
}

TEST_F(PacketTest, TestSetGetSrcPort) {
  try {
    auto p =
        PacketForTest(Packet::WRAP_BUFFER,
                      &raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32][0],
                      raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32].size(),
                      raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32].size());
    // Let's make compiler happy
    p.setSrcPort(12345);
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  packet.setSrcPort(12345);
  EXPECT_EQ(packet.getSrcPort(), 12345);
}

TEST_F(PacketTest, TestSetGetDstPort) {
  try {
    auto p =
        PacketForTest(Packet::WRAP_BUFFER,
                      &raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32][0],
                      raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32].size(),
                      raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32].size());
    // Let's make compiler happy
    p.setDstPort(12345);
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  packet.setDstPort(12345);
  EXPECT_EQ(packet.getDstPort(), 12345);
}

TEST_F(PacketTest, TestEnsureCapacity) {
  PacketForTest &p = packet;

  // This shoul be false
  auto ret = p.ensureCapacity(
      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size() + 10);
  EXPECT_FALSE(ret);

  // This should be true
  ret =
      p.ensureCapacity(raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size());
  EXPECT_TRUE(ret);

  // This should be true
  ret = p.ensureCapacity(
      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size() - 10);
  EXPECT_TRUE(ret);

  // Try to trim the packet start
  p.trimStart(10);
  // Now this should be false
  ret =
      p.ensureCapacity(raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size());
  EXPECT_FALSE(ret);

  // Create a new packet
  auto p2 =
      PacketForTest(Packet::WRAP_BUFFER,
                    &raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32][0],
                    raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32].size(),
                    raw_packets_[HICN_PACKET_FORMAT_IPV6_ICMP.as_u32].size());

  p2.appendPayload(utils::MemBuf::createCombined(2000));

  // This should be false, since the buffer is chained
  ret = p2.ensureCapacity(
      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size() - 10);
  EXPECT_FALSE(ret);
}

//
// This test is disabled as it manipulates a ipv6 header with the wrong payload
// length inside.
//
TEST_F(PacketTest, DISABLED_TestEnsureCapacityAndFillUnused) {
  // Create packet by excluding the payload (So only L3 + L4 headers). The
  // payload will be trated as unused tailroom
  PacketForTest p = PacketForTest(
      Packet::WRAP_BUFFER, &raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32][0],
      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size() - PAYLOAD_SIZE,
      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size());

  // Copy original packet payload, which is here trated as a unused tailroom
  uint8_t original_payload[PAYLOAD_SIZE];
  uint8_t *payload = &raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32][0] +
                     raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size() -
                     PAYLOAD_SIZE;
  std::memcpy(original_payload, payload, PAYLOAD_SIZE);

  // This should be true and the unused tailroom should be unmodified
  auto ret = p.ensureCapacityAndFillUnused(
      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size() -
          (PAYLOAD_SIZE + 10),
      0);
  EXPECT_TRUE(ret);
  ret = std::memcmp(original_payload, payload, PAYLOAD_SIZE);
  EXPECT_EQ(ret, 0);

  // This should fill the payload with zeros
  ret = p.ensureCapacityAndFillUnused(
      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size(), 0);
  EXPECT_TRUE(ret);
  uint8_t zeros[PAYLOAD_SIZE];
  std::memset(zeros, 0, PAYLOAD_SIZE);
  ret = std::memcmp(payload, zeros, PAYLOAD_SIZE);
  EXPECT_EQ(ret, 0);

  // This should fill the payload with ones
  ret = p.ensureCapacityAndFillUnused(
      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size(), 1);
  EXPECT_TRUE(ret);
  uint8_t ones[PAYLOAD_SIZE];
  std::memset(ones, 1, PAYLOAD_SIZE);
  ret = std::memcmp(payload, ones, PAYLOAD_SIZE);
  EXPECT_EQ(ret, 0);

  // This should return false and the payload should be unmodified
  ret = p.ensureCapacityAndFillUnused(
      raw_packets_[HICN_PACKET_FORMAT_IPV6_TCP.as_u32].size() + 1, 1);
  EXPECT_FALSE(ret);
  ret = std::memcmp(payload, ones, PAYLOAD_SIZE);
  EXPECT_EQ(ret, 0);
}

TEST_F(PacketTest, TestSetGetTTL) {
  packet.setTTL(128);
  EXPECT_EQ(packet.getTTL(), 128);
}

}  // namespace core
}  // namespace transport
