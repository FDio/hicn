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
#include <hicn/transport/core/interest.h>
#include <hicn/transport/errors/not_implemented_exception.h>
#include <test/packet_samples.h>

#include <climits>
#include <random>
#include <vector>

namespace transport {

namespace core {

namespace {
// The fixture for testing class Foo.
class InterestTest : public ::testing::Test {
 protected:
  InterestTest() : name_("b001::123|321"), interest_(HF_INET6_TCP) {
    // You can do set-up work for each test here.
  }

  virtual ~InterestTest() {
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

  Interest interest_;

  std::vector<uint8_t> buffer_ = {// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
                                  IPV6_HEADER(TCP_PROTO, 20 + PAYLOAD_SIZE),
                                  // ICMP6 echo request
                                  TCP_HEADER(0x00),
                                  // Payload
                                  PAYLOAD};
};

void testFormatConstructor(Packet::Format format = HF_UNSPEC) {
  try {
    Interest interest(format, 0);
  } catch (...) {
    FAIL() << "ERROR: Unexpected exception thrown for " << format;
  }
}

void testFormatConstructorException(Packet::Format format = HF_UNSPEC) {
  try {
    Interest interest(format, 0);
    FAIL() << "We expected an exception here";
  } catch (errors::MalformedPacketException &exc) {
    // Ok right exception
  } catch (...) {
    FAIL() << "Wrong exception thrown";
  }
}

}  // namespace

TEST_F(InterestTest, ConstructorWithFormat) {
  /**
   * Without arguments it should be format = HF_UNSPEC.
   * We expect a crash.
   */

  testFormatConstructor(Packet::Format::HF_INET_TCP);
  testFormatConstructor(Packet::Format::HF_INET6_TCP);
  testFormatConstructorException(Packet::Format::HF_INET_ICMP);
  testFormatConstructorException(Packet::Format::HF_INET6_ICMP);
  testFormatConstructor(Packet::Format::HF_INET_TCP_AH);
  testFormatConstructor(Packet::Format::HF_INET6_TCP_AH);
  testFormatConstructorException(Packet::Format::HF_INET_ICMP_AH);
  testFormatConstructorException(Packet::Format::HF_INET6_ICMP_AH);
}

TEST_F(InterestTest, ConstructorWithName) {
  /**
   * Without arguments it should be format = HF_UNSPEC.
   * We expect a crash.
   */
  Name n("b001::1|123");

  try {
    Interest interest(HF_INET6_TCP, n);
  } catch (...) {
    FAIL() << "ERROR: Unexpected exception thrown";
  }
}

TEST_F(InterestTest, ConstructorWithBuffer) {
  // Ensure buffer is interest
  auto ret = Interest::isInterest(&buffer_[0]);
  EXPECT_TRUE(ret);

  // Create interest from buffer
  try {
    Interest interest(Interest::COPY_BUFFER, &buffer_[0], buffer_.size());
  } catch (...) {
    FAIL() << "ERROR: Unexpected exception thrown";
  }

  std::vector<uint8_t> buffer2{// IPv6 src=b001::ab:cdab:cdef, dst=b002::ca
                               IPV6_HEADER(ICMP6_PROTO, 60 + 44),
                               // ICMP6 echo request
                               TCP_HEADER(0x00),
                               // Payload
                               PAYLOAD};

  // Ensure this throws an exception
  try {
    Interest interest(Interest::COPY_BUFFER, &buffer2[0], buffer2.size());
    FAIL() << "We expected an exception here";
  } catch (errors::MalformedPacketException &exc) {
    // Ok right exception
  } catch (...) {
    FAIL() << "Wrong exception thrown";
  }
}

TEST_F(InterestTest, SetGetName) {
  // Create interest from buffer
  Interest interest(Interest::COPY_BUFFER, &buffer_[0], buffer_.size());

  // Get name
  auto n = interest.getName();

  // ensure name is b002::ca|1
  Name n2("b002::ca|1");
  auto ret = (n == n2);

  EXPECT_TRUE(ret);

  Name n3("b003::1234|1234");

  // Change name to b003::1234|1234
  interest.setName(n3);

  // Check name was set
  n = interest.getName();
  ret = (n == n3);
  EXPECT_TRUE(ret);
}

TEST_F(InterestTest, SetGetLocator) {
  // Create interest from buffer
  Interest interest(Interest::COPY_BUFFER, &buffer_[0], buffer_.size());

  // Get locator
  auto l = interest.getLocator();

  ip_address_t address;
  inet_pton(AF_INET6, "b006::ab:cdab:cdef", &address);
  auto ret = !ip_address_cmp(&l, &address, AF_INET6);

  EXPECT_TRUE(ret);

  // Set different locator
  inet_pton(AF_INET6, "2001::1234::4321::abcd::", &address);

  // Set it on interest
  interest.setLocator(address);

  // Check it was set
  l = interest.getLocator();
  ret = !ip_address_cmp(&l, &address, AF_INET6);

  EXPECT_TRUE(ret);
}

TEST_F(InterestTest, SetGetLifetime) {
  // Create interest from buffer
  Interest interest(HF_INET6_TCP);
  const constexpr uint32_t lifetime = 10000;

  // Set lifetime
  interest.setLifetime(lifetime);

  // Get lifetime
  auto l = interest.getLifetime();

  // Ensure they are the same
  EXPECT_EQ(l, lifetime);
}

TEST_F(InterestTest, HasManifest) {
  // Create interest from buffer
  Interest interest(HF_INET6_TCP);

  // Let's expect anexception here
  try {
    interest.setPayloadType(PayloadType::UNSPECIFIED);
    FAIL() << "We expect an esception here";
  } catch (errors::RuntimeException &exc) {
    // Ok right exception
  } catch (...) {
    FAIL() << "Wrong exception thrown";
  }

  interest.setPayloadType(PayloadType::DATA);
  EXPECT_FALSE(interest.hasManifest());

  interest.setPayloadType(PayloadType::MANIFEST);
  EXPECT_TRUE(interest.hasManifest());
}

TEST_F(InterestTest, AppendSuffixesEncodeAndIterate) {
  // Create interest from buffer
  Interest interest(HF_INET6_TCP);

  // Appenad some suffixes, with some duplicates
  interest.appendSuffix(1);
  interest.appendSuffix(2);
  interest.appendSuffix(5);
  interest.appendSuffix(3);
  interest.appendSuffix(4);
  interest.appendSuffix(5);
  interest.appendSuffix(5);
  interest.appendSuffix(5);
  interest.appendSuffix(5);
  interest.appendSuffix(5);

  // Encode them in wire format
  interest.encodeSuffixes();

  // Iterate over them. They should be in order and without repetitions
  auto suffix = interest.firstSuffix();
  auto n_suffixes = interest.numberOfSuffixes();

  for (uint32_t i = 0; i < n_suffixes; i++) {
    EXPECT_EQ(*(suffix + i), (i + 1));
  }
}

TEST_F(InterestTest, AppendSuffixesWithGaps) {
  // Create interest from buffer
  Interest interest(HF_INET6_TCP);

  // Appenad some suffixes, out of order and with gaps
  interest.appendSuffix(6);
  interest.appendSuffix(2);
  interest.appendSuffix(5);
  interest.appendSuffix(1);

  // Encode them in wire format
  interest.encodeSuffixes();
  EXPECT_TRUE(interest.hasManifest());

  // Check first suffix correctness
  auto suffix = interest.firstSuffix();
  EXPECT_NE(suffix, nullptr);
  EXPECT_EQ(*suffix, 1U);

  // Iterate over them. They should be in order and without repetitions
  std::vector<uint32_t> expected = {1, 2, 5, 6};
  EXPECT_EQ(interest.numberOfSuffixes(), expected.size());

  for (uint32_t seq : expected) {
    EXPECT_EQ(*suffix, seq);
    suffix++;
  }
}

TEST_F(InterestTest, InterestWithoutManifest) {
  // Create interest without manifest
  Interest interest(HF_INET6_TCP);
  auto suffix = interest.firstSuffix();

  EXPECT_FALSE(interest.hasManifest());
  EXPECT_EQ(interest.numberOfSuffixes(), 0U);
  EXPECT_EQ(suffix, nullptr);
}

}  // namespace core
}  // namespace transport
