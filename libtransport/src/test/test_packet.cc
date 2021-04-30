/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
#include <test/packet_samples.h>

#include <climits>
#include <random>
#include <vector>

namespace transport {

namespace core {

/**
 * Since packet is an abstract class, we derive a concrete class to be used for
 * the test.
 */
class PacketForTest : public Packet {
 public:
  template <typename... Args>
  PacketForTest(Args &&... args) : Packet(std::forward<Args>(args)...) {}

  virtual ~PacketForTest() {}

  const Name &getName() const override {
    throw errors::NotImplementedException();
  }

  Name &getWritableName() override { throw errors::NotImplementedException(); }

  void setName(const Name &name) override {
    throw errors::NotImplementedException();
  }

  void setName(Name &&name) override {
    throw errors::NotImplementedException();
  }

  void setLifetime(uint32_t lifetime) override {
    throw errors::NotImplementedException();
  }

  uint32_t getLifetime() const override {
    throw errors::NotImplementedException();
  }

  void setLocator(const ip_address_t &locator) override {
    throw errors::NotImplementedException();
  }

  void resetForHash() override { throw errors::NotImplementedException(); }

  ip_address_t getLocator() const override {
    throw errors::NotImplementedException();
  }
};

namespace {
// The fixture for testing class Foo.
class PacketTest : public ::testing::Test {
 protected:
  PacketTest()
      : name_("b001::123|321"),
        packet(Packet::COPY_BUFFER, &raw_packets_[HF_INET6_TCP][0],
               raw_packets_[HF_INET6_TCP].size()) {
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

  static std::map<Packet::Format, std::vector<uint8_t>> raw_packets_;

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

std::map<Packet::Format, std::vector<uint8_t>> PacketTest::raw_packets_ = {
    {Packet::Format::HF_INET6_TCP,

     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV6_HEADER(TCP_PROTO, 20 + PAYLOAD_SIZE),
      // TCP src=0x1234 dst=0x4321, seq=0x0001
      TCP_HEADER(0x00),
      // Payload
      PAYLOAD}},

    {Packet::Format::HF_INET_TCP,
     {// IPv4 src=3.13.127.8, dst=192.168.1.92
      IPV4_HEADER(TCP_PROTO, 20 + PAYLOAD_SIZE),
      // TCP src=0x1234 dst=0x4321, seq=0x0001
      TCP_HEADER(0x00),
      // Other
      PAYLOAD}},

    {Packet::Format::HF_INET_ICMP,
     {// IPv4 src=3.13.127.8, dst=192.168.1.92
      IPV4_HEADER(ICMP_PROTO, 64),
      // ICMP echo request
      ICMP_ECHO_REQUEST}},

    {Packet::Format::HF_INET6_ICMP,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV6_HEADER(ICMP6_PROTO, 60),
      // ICMP6 echo request
      ICMP6_ECHO_REQUEST}},

    {Packet::Format::HF_INET6_TCP_AH,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV6_HEADER(TCP_PROTO, 20 + 44 + 128),
      // ICMP6 echo request
      TCP_HEADER(0x18),
      // hICN AH header
      AH_HEADER}},

    {Packet::Format::HF_INET_TCP_AH,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV4_HEADER(TCP_PROTO, 20 + 44 + 128),
      // ICMP6 echo request
      TCP_HEADER(0x18),
      // hICN AH header
      AH_HEADER}},

    // XXX No flag defined in ICMP header to signal AH header.
    {Packet::Format::HF_INET_ICMP_AH,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV4_HEADER(ICMP_PROTO, 64 + 44),
      // ICMP6 echo request
      ICMP_ECHO_REQUEST,
      // hICN AH header
      AH_HEADER}},

    {Packet::Format::HF_INET6_ICMP_AH,
     {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
      IPV6_HEADER(ICMP6_PROTO, 60 + 44),
      // ICMP6 echo request
      ICMP6_ECHO_REQUEST,
      // hICN AH header
      AH_HEADER}},

};

void testFormatConstructor(Packet::Format format = HF_UNSPEC) {
  try {
    PacketForTest packet(format);
  } catch (...) {
    FAIL() << "ERROR: Unexpected exception thrown for " << format;
  }
}

void testFormatAndAdditionalHeaderConstructor(Packet::Format format,
                                              std::size_t additional_header) {
  PacketForTest packet(format, additional_header);
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
    EXPECT_EQ(p.getFormat(), format);

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

    // Format should fallback to HF_UNSPEC
    EXPECT_EQ(p.getFormat(), HF_UNSPEC);
  } catch (...) {
    FAIL() << "ERROR: Unexpected exception thrown.";
  }
}

void getHeaderSizeFromBuffer(Packet::Format format,
                             std::vector<uint8_t> &packet,
                             std::size_t expected) {
  auto header_size = PacketForTest::getHeaderSizeFromBuffer(format, &packet[0]);
  EXPECT_EQ(header_size, expected);
}

void getHeaderSizeFromFormat(Packet::Format format, std::size_t expected) {
  auto header_size = PacketForTest::getHeaderSizeFromFormat(format);
  EXPECT_EQ(header_size, expected);
}

void getPayloadSizeFromBuffer(Packet::Format format,
                              std::vector<uint8_t> &packet,
                              std::size_t expected) {
  auto payload_size =
      PacketForTest::getPayloadSizeFromBuffer(format, &packet[0]);
  EXPECT_EQ(payload_size, expected);
}

void getFormatFromBuffer(Packet::Format expected,
                         std::vector<uint8_t> &packet) {
  auto format = PacketForTest::getFormatFromBuffer(&packet[0], packet.size());
  EXPECT_EQ(format, expected);
}

void getHeaderSize(std::size_t expected, const PacketForTest &packet) {
  auto size = packet.headerSize();
  EXPECT_EQ(size, expected);
}

void testGetFormat(Packet::Format expected, const Packet &packet) {
  auto format = packet.getFormat();
  EXPECT_EQ(format, expected);
}

}  // namespace

TEST_F(PacketTest, ConstructorWithFormat) {
  testFormatConstructor(Packet::Format::HF_INET_TCP);
  testFormatConstructor(Packet::Format::HF_INET6_TCP);
  testFormatConstructor(Packet::Format::HF_INET_ICMP);
  testFormatConstructor(Packet::Format::HF_INET6_ICMP);
  testFormatConstructor(Packet::Format::HF_INET_TCP_AH);
  testFormatConstructor(Packet::Format::HF_INET6_TCP_AH);
  testFormatConstructor(Packet::Format::HF_INET_ICMP_AH);
  testFormatConstructor(Packet::Format::HF_INET6_ICMP_AH);
}

TEST_F(PacketTest, ConstructorWithFormatAndAdditionalHeader) {
  testFormatAndAdditionalHeaderConstructor(Packet::Format::HF_INET_TCP, 123);
  testFormatAndAdditionalHeaderConstructor(Packet::Format::HF_INET6_TCP, 360);
  testFormatAndAdditionalHeaderConstructor(Packet::Format::HF_INET_ICMP, 21);
  testFormatAndAdditionalHeaderConstructor(Packet::Format::HF_INET6_ICMP, 444);
  testFormatAndAdditionalHeaderConstructor(Packet::Format::HF_INET_TCP_AH, 555);
  testFormatAndAdditionalHeaderConstructor(Packet::Format::HF_INET6_TCP_AH,
                                           321);
  testFormatAndAdditionalHeaderConstructor(Packet::Format::HF_INET_ICMP_AH,
                                           123);
  testFormatAndAdditionalHeaderConstructor(Packet::Format::HF_INET6_ICMP_AH,
                                           44);
}

TEST_F(PacketTest, ConstructorWithNew) {
  auto &_packet = raw_packets_[HF_INET6_TCP];
  auto packet_ptr = new PacketForTest(Packet::WRAP_BUFFER, &_packet[0],
                                      _packet.size(), _packet.size());
  (void)packet_ptr;
}

TEST_F(PacketTest, ConstructorWithRawBufferInet6Tcp) {
  auto format = Packet::Format::HF_INET6_TCP;
  testRawBufferConstructor(raw_packets_[format], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInetTcp) {
  auto format = Packet::Format::HF_INET_TCP;
  testRawBufferConstructor(raw_packets_[format], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInetIcmp) {
  auto format = Packet::Format::HF_INET_ICMP;
  testRawBufferConstructor(raw_packets_[format], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInet6Icmp) {
  auto format = Packet::Format::HF_INET6_ICMP;
  testRawBufferConstructor(raw_packets_[format], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInet6TcpAh) {
  auto format = Packet::Format::HF_INET6_TCP_AH;
  testRawBufferConstructor(raw_packets_[format], format);
}

TEST_F(PacketTest, ConstructorWithRawBufferInetTcpAh) {
  auto format = Packet::Format::HF_INET_TCP_AH;
  testRawBufferConstructor(raw_packets_[format], format);
}

TEST_F(PacketTest, MoveConstructor) {
  PacketForTest p0(Packet::Format::HF_INET6_TCP);
  PacketForTest p1(std::move(p0));
  EXPECT_EQ(p0.getFormat(), Packet::Format::HF_UNSPEC);
  EXPECT_EQ(p1.getFormat(), Packet::Format::HF_INET6_TCP);
}

TEST_F(PacketTest, TestGetHeaderSizeFromBuffer) {
  getHeaderSizeFromBuffer(HF_INET6_TCP, raw_packets_[HF_INET6_TCP],
                          HICN_V6_TCP_HDRLEN);
  getHeaderSizeFromBuffer(HF_INET_TCP, raw_packets_[HF_INET_TCP],
                          HICN_V4_TCP_HDRLEN);
  getHeaderSizeFromBuffer(HF_INET6_ICMP, raw_packets_[HF_INET6_ICMP],
                          IPV6_HDRLEN + 4);
  getHeaderSizeFromBuffer(HF_INET_ICMP, raw_packets_[HF_INET_ICMP],
                          IPV4_HDRLEN + 4);
  getHeaderSizeFromBuffer(HF_INET6_TCP_AH, raw_packets_[HF_INET6_TCP_AH],
                          HICN_V6_TCP_AH_HDRLEN + 128);
  getHeaderSizeFromBuffer(HF_INET_TCP_AH, raw_packets_[HF_INET_TCP_AH],
                          HICN_V4_TCP_AH_HDRLEN + 128);
}

TEST_F(PacketTest, TestGetHeaderSizeFromFormat) {
  getHeaderSizeFromFormat(HF_INET6_TCP, HICN_V6_TCP_HDRLEN);
  getHeaderSizeFromFormat(HF_INET_TCP, HICN_V4_TCP_HDRLEN);
  getHeaderSizeFromFormat(HF_INET6_ICMP, IPV6_HDRLEN + 4);
  getHeaderSizeFromFormat(HF_INET_ICMP, IPV4_HDRLEN + 4);
  getHeaderSizeFromFormat(HF_INET6_TCP_AH, HICN_V6_TCP_AH_HDRLEN);
  getHeaderSizeFromFormat(HF_INET_TCP_AH, HICN_V4_TCP_AH_HDRLEN);
}

TEST_F(PacketTest, TestGetPayloadSizeFromBuffer) {
  getPayloadSizeFromBuffer(HF_INET6_TCP, raw_packets_[HF_INET6_TCP], 12);
  getPayloadSizeFromBuffer(HF_INET_TCP, raw_packets_[HF_INET_TCP], 12);
  getPayloadSizeFromBuffer(HF_INET6_ICMP, raw_packets_[HF_INET6_ICMP], 56);
  getPayloadSizeFromBuffer(HF_INET_ICMP, raw_packets_[HF_INET_ICMP], 60);
  getPayloadSizeFromBuffer(HF_INET6_TCP_AH, raw_packets_[HF_INET6_TCP_AH], 0);
  getPayloadSizeFromBuffer(HF_INET_TCP_AH, raw_packets_[HF_INET_TCP_AH], 0);
}

TEST_F(PacketTest, TestIsInterest) {
  auto ret = PacketForTest::isInterest(&raw_packets_[HF_INET6_TCP][0]);

  EXPECT_TRUE(ret);
}

TEST_F(PacketTest, TestGetFormatFromBuffer) {
  getFormatFromBuffer(HF_INET6_TCP, raw_packets_[HF_INET6_TCP]);
  getFormatFromBuffer(HF_INET_TCP, raw_packets_[HF_INET_TCP]);
  getFormatFromBuffer(HF_INET6_ICMP, raw_packets_[HF_INET6_ICMP]);
  getFormatFromBuffer(HF_INET_ICMP, raw_packets_[HF_INET_ICMP]);
  getFormatFromBuffer(HF_INET6_TCP_AH, raw_packets_[HF_INET6_TCP_AH]);
  getFormatFromBuffer(HF_INET_TCP_AH, raw_packets_[HF_INET_TCP_AH]);
}

// TEST_F(PacketTest, TestReplace) {
//   PacketForTest packet(Packet::WRAP_BUFFER, &raw_packets_[HF_INET6_TCP][0],
//                        raw_packets_[HF_INET6_TCP].size());

//   // Replace current packet with another one
//   packet.replace(&raw_packets_[HF_INET_TCP][0],
//                  raw_packets_[HF_INET_TCP].size());

//   // Check new format
//   ASSERT_EQ(packet.getFormat(), HF_INET_TCP);
// }

TEST_F(PacketTest, TestPayloadSize) {
  // Check payload size of existing packet
  auto &_packet = raw_packets_[HF_INET6_TCP];
  PacketForTest packet(Packet::WRAP_BUFFER, &_packet[0], _packet.size(),
                       _packet.size());

  EXPECT_EQ(packet.payloadSize(), std::size_t(PAYLOAD_SIZE));

  // Check for dynamic generated packet
  std::string payload0(1024, 'X');

  // Create the packet
  PacketForTest packet2(HF_INET6_TCP);

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
  getHeaderSize(HICN_V6_TCP_HDRLEN,
                PacketForTest(Packet::Format::HF_INET6_TCP));
  getHeaderSize(HICN_V4_TCP_HDRLEN, PacketForTest(Packet::Format::HF_INET_TCP));
  getHeaderSize(HICN_V6_ICMP_HDRLEN,
                PacketForTest(Packet::Format::HF_INET6_ICMP));
  getHeaderSize(HICN_V4_ICMP_HDRLEN,
                PacketForTest(Packet::Format::HF_INET_ICMP));
  getHeaderSize(HICN_V6_TCP_AH_HDRLEN,
                PacketForTest(Packet::Format::HF_INET6_TCP_AH));
  getHeaderSize(HICN_V4_TCP_AH_HDRLEN,
                PacketForTest(Packet::Format::HF_INET_TCP_AH));
}

TEST_F(PacketTest, TestMemBufReference) {
  // Create packet
  auto &_packet = raw_packets_[HF_INET6_TCP];

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
  EXPECT_EQ(packet.getFormat(), HF_INET6_TCP);
  EXPECT_EQ(packet.length(), raw_packets_[HF_INET6_TCP].size());
  EXPECT_EQ(packet.headerSize(), HICN_V6_TCP_HDRLEN);
  EXPECT_EQ(packet.payloadSize(), packet.length() - packet.headerSize());

  // Reset the packet
  packet.reset();

  // Rerun test
  EXPECT_EQ(packet.getFormat(), HF_UNSPEC);
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
  EXPECT_EQ(packet.getFormat(), HF_UNSPEC);
  EXPECT_EQ(packet.length(), std::size_t(0));
  EXPECT_EQ(packet.headerSize(), std::size_t(0));
  EXPECT_EQ(packet.payloadSize(), std::size_t(0));
}

TEST_F(PacketTest, GetPayload) {
  // Append payload with raw buffer
  uint8_t raw_buffer[2048];
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
                     &raw_packets_[Packet::Format::HF_INET_TCP][0],
                     raw_packets_[Packet::Format::HF_INET_TCP].size(),
                     raw_packets_[Packet::Format::HF_INET_TCP].size());
    testGetFormat(Packet::Format::HF_INET_TCP, p0);

    PacketForTest p1(Packet::WRAP_BUFFER,
                     &raw_packets_[Packet::Format::HF_INET6_TCP][0],
                     raw_packets_[Packet::Format::HF_INET6_TCP].size(),
                     raw_packets_[Packet::Format::HF_INET6_TCP].size());
    testGetFormat(Packet::Format::HF_INET6_TCP, p1);

    PacketForTest p2(Packet::WRAP_BUFFER,
                     &raw_packets_[Packet::Format::HF_INET_ICMP][0],
                     raw_packets_[Packet::Format::HF_INET_ICMP].size(),
                     raw_packets_[Packet::Format::HF_INET_ICMP].size());
    testGetFormat(Packet::Format::HF_INET_ICMP, p2);

    PacketForTest p3(Packet::WRAP_BUFFER,
                     &raw_packets_[Packet::Format::HF_INET6_ICMP][0],
                     raw_packets_[Packet::Format::HF_INET6_ICMP].size(),
                     raw_packets_[Packet::Format::HF_INET6_ICMP].size());
    testGetFormat(Packet::Format::HF_INET6_ICMP, p3);

    PacketForTest p4(Packet::WRAP_BUFFER,
                     &raw_packets_[Packet::Format::HF_INET_TCP_AH][0],
                     raw_packets_[Packet::Format::HF_INET_TCP_AH].size(),
                     raw_packets_[Packet::Format::HF_INET_TCP_AH].size());
    testGetFormat(Packet::Format::HF_INET_TCP_AH, p4);

    PacketForTest p5(Packet::WRAP_BUFFER,
                     &raw_packets_[Packet::Format::HF_INET6_TCP_AH][0],
                     raw_packets_[Packet::Format::HF_INET6_TCP_AH].size(),
                     raw_packets_[Packet::Format::HF_INET6_TCP_AH].size());
    testGetFormat(Packet::Format::HF_INET6_TCP_AH, p5);
  }

  // Let's try now creating empty packets
  {
    PacketForTest p0(Packet::Format::HF_INET_TCP);
    testGetFormat(Packet::Format::HF_INET_TCP, p0);

    PacketForTest p1(Packet::Format::HF_INET6_TCP);
    testGetFormat(Packet::Format::HF_INET6_TCP, p1);

    PacketForTest p2(Packet::Format::HF_INET_ICMP);
    testGetFormat(Packet::Format::HF_INET_ICMP, p2);

    PacketForTest p3(Packet::Format::HF_INET6_ICMP);
    testGetFormat(Packet::Format::HF_INET6_ICMP, p3);

    PacketForTest p4(Packet::Format::HF_INET_TCP_AH);
    testGetFormat(Packet::Format::HF_INET_TCP_AH, p4);

    PacketForTest p5(Packet::Format::HF_INET6_TCP_AH);
    testGetFormat(Packet::Format::HF_INET6_TCP_AH, p5);
  }
}

TEST_F(PacketTest, SetGetTestSignatureTimestamp) {
  // Let's try to set the signature timestamp in a packet without AH header. We
  // expect an exception.
  using namespace std::chrono;
  uint64_t now =
      duration_cast<milliseconds>(system_clock::now().time_since_epoch())
          .count();

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
  PacketForTest p(HF_INET6_TCP_AH);
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
  PacketForTest p(HF_INET6_TCP_AH);
  p.setValidationAlgorithm(auth::CryptoSuite::RSA_SHA256);
  auto v_get = p.getValidationAlgorithm();

  // Check we got the right value
  EXPECT_EQ(v_get, auth::CryptoSuite::RSA_SHA256);
}

TEST_F(PacketTest, TestSetGetKeyId) {
  uint8_t key[32];
  auth::KeyId key_id = std::make_pair(key, sizeof(key));

  try {
    packet.setKeyId(key_id);
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  // Same fot get method
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
  PacketForTest p(HF_INET6_TCP_AH);
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
  PacketForTest p(HF_INET6_TCP_AH, 300);
  std::string payload(5000, 'X');
  p.appendPayload((const uint8_t *)payload.c_str(), payload.size() / 2);
  p.appendPayload((const uint8_t *)(payload.c_str() + payload.size() / 2),
                  payload.size() / 2);

  p.setChecksum();
  integrity = p.checkIntegrity();
  EXPECT_TRUE(integrity);
}

TEST_F(PacketTest, TestSetSyn) {
  // Test syn of non-tcp format and check exception is thrown
  try {
    auto p = PacketForTest(Packet::WRAP_BUFFER, &raw_packets_[HF_INET6_ICMP][0],
                           raw_packets_[HF_INET6_ICMP].size(),
                           raw_packets_[HF_INET6_ICMP].size());
    // Let's make compiler happy
    p.setSyn();
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  packet.setSyn();
  EXPECT_TRUE(packet.testSyn());

  packet.resetSyn();
  EXPECT_FALSE(packet.testSyn());
}

TEST_F(PacketTest, TestSetFin) {
  // Test syn of non-tcp format and check exception is thrown
  try {
    auto p = PacketForTest(Packet::WRAP_BUFFER, &raw_packets_[HF_INET6_ICMP][0],
                           raw_packets_[HF_INET6_ICMP].size(),
                           raw_packets_[HF_INET6_ICMP].size());
    // Let's make compiler happy
    p.setFin();
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  packet.setFin();
  EXPECT_TRUE(packet.testFin());

  packet.resetFin();
  EXPECT_FALSE(packet.testFin());
}

TEST_F(PacketTest, TestSetAck) {
  // Test syn of non-tcp format and check exception is thrown
  try {
    auto p = PacketForTest(Packet::WRAP_BUFFER, &raw_packets_[HF_INET6_ICMP][0],
                           raw_packets_[HF_INET6_ICMP].size(),
                           raw_packets_[HF_INET6_ICMP].size());
    // Let's make compiler happy
    p.setAck();
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  packet.setAck();
  EXPECT_TRUE(packet.testAck());

  packet.resetAck();
  EXPECT_FALSE(packet.testAck());
}

TEST_F(PacketTest, TestSetRst) {
  // Test syn of non-tcp format and check exception is thrown
  try {
    auto p = PacketForTest(Packet::WRAP_BUFFER, &raw_packets_[HF_INET6_ICMP][0],
                           raw_packets_[HF_INET6_ICMP].size(),
                           raw_packets_[HF_INET6_ICMP].size());
    // Let's make compiler happy
    p.setRst();
    FAIL() << "We should not reach this point.";
  } catch (const errors::RuntimeException &exc) {
    /* ok right exception*/
  } catch (...) {
    FAIL() << "Unexpected exception";
  }

  packet.setRst();
  EXPECT_TRUE(packet.testRst());

  packet.resetRst();
  EXPECT_FALSE(packet.testRst());
}

TEST_F(PacketTest, TestResetFlags) {
  packet.setRst();
  packet.setSyn();
  packet.setAck();
  packet.setFin();
  EXPECT_TRUE(packet.testRst());
  EXPECT_TRUE(packet.testAck());
  EXPECT_TRUE(packet.testFin());
  EXPECT_TRUE(packet.testSyn());

  packet.resetFlags();
  EXPECT_FALSE(packet.testRst());
  EXPECT_FALSE(packet.testAck());
  EXPECT_FALSE(packet.testFin());
  EXPECT_FALSE(packet.testSyn());
}

TEST_F(PacketTest, TestSetGetSrcPort) {
  try {
    auto p = PacketForTest(Packet::WRAP_BUFFER, &raw_packets_[HF_INET6_ICMP][0],
                           raw_packets_[HF_INET6_ICMP].size(),
                           raw_packets_[HF_INET6_ICMP].size());
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
    auto p = PacketForTest(Packet::WRAP_BUFFER, &raw_packets_[HF_INET6_ICMP][0],
                           raw_packets_[HF_INET6_ICMP].size(),
                           raw_packets_[HF_INET6_ICMP].size());
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
  auto ret = p.ensureCapacity(raw_packets_[HF_INET6_TCP].size() + 10);
  EXPECT_FALSE(ret);

  // This should be true
  ret = p.ensureCapacity(raw_packets_[HF_INET6_TCP].size());
  EXPECT_TRUE(ret);

  // This should be true
  ret = p.ensureCapacity(raw_packets_[HF_INET6_TCP].size() - 10);
  EXPECT_TRUE(ret);

  // Try to trim the packet start
  p.trimStart(10);
  // Now this should be false
  ret = p.ensureCapacity(raw_packets_[HF_INET6_TCP].size());
  EXPECT_FALSE(ret);

  // Create a new packet
  auto p2 = PacketForTest(Packet::WRAP_BUFFER, &raw_packets_[HF_INET6_ICMP][0],
                          raw_packets_[HF_INET6_ICMP].size(),
                          raw_packets_[HF_INET6_ICMP].size());

  p2.appendPayload(utils::MemBuf::createCombined(2000));

  // This should be false, since the buffer is chained
  ret = p2.ensureCapacity(raw_packets_[HF_INET6_TCP].size() - 10);
  EXPECT_FALSE(ret);
}

TEST_F(PacketTest, TestEnsureCapacityAndFillUnused) {
  // Create packet by excluding the payload (So only L3 + L4 headers). The
  // payload will be trated as unused tailroom
  PacketForTest p =
      PacketForTest(Packet::WRAP_BUFFER, &raw_packets_[HF_INET6_TCP][0],
                    raw_packets_[HF_INET6_TCP].size() - PAYLOAD_SIZE,
                    raw_packets_[HF_INET6_TCP].size());

  // Copy original packet payload, which is here trated as a unused tailroom
  uint8_t original_payload[PAYLOAD_SIZE];
  uint8_t *payload = &raw_packets_[HF_INET6_TCP][0] +
                     raw_packets_[HF_INET6_TCP].size() - PAYLOAD_SIZE;
  std::memcpy(original_payload, payload, PAYLOAD_SIZE);

  // This should be true and the unused tailroom should be unmodified
  auto ret = p.ensureCapacityAndFillUnused(
      raw_packets_[HF_INET6_TCP].size() - (PAYLOAD_SIZE + 10), 0);
  EXPECT_TRUE(ret);
  ret = std::memcmp(original_payload, payload, PAYLOAD_SIZE);
  EXPECT_EQ(ret, 0);

  // This should fill the payload with zeros
  ret = p.ensureCapacityAndFillUnused(raw_packets_[HF_INET6_TCP].size(), 0);
  EXPECT_TRUE(ret);
  uint8_t zeros[PAYLOAD_SIZE];
  std::memset(zeros, 0, PAYLOAD_SIZE);
  ret = std::memcmp(payload, zeros, PAYLOAD_SIZE);
  EXPECT_EQ(ret, 0);

  // This should fill the payload with ones
  ret = p.ensureCapacityAndFillUnused(raw_packets_[HF_INET6_TCP].size(), 1);
  EXPECT_TRUE(ret);
  uint8_t ones[PAYLOAD_SIZE];
  std::memset(ones, 1, PAYLOAD_SIZE);
  ret = std::memcmp(payload, ones, PAYLOAD_SIZE);
  EXPECT_EQ(ret, 0);

  // This should return false and the payload should be unmodified
  ret = p.ensureCapacityAndFillUnused(raw_packets_[HF_INET6_TCP].size() + 1, 1);
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

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
