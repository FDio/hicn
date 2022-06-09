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
#include <hicn/transport/core/prefix.h>
#include <hicn/transport/errors/invalid_ip_address_exception.h>
#include <hicn/transport/portability/endianess.h>

#include <cstring>
#include <memory>
#include <vector>

namespace transport {
namespace core {

namespace {
class PrefixTest : public ::testing::Test {
 protected:
  static inline const char prefix_str0[] = "2001:db8:1::/64";
  static inline const char prefix_str1[] = "10.11.12.0/24";
  static inline const char prefix_str2[] = "2001:db8:1::abcd/64";
  static inline const char prefix_str3[] = "10.11.12.245/27";
  static inline const char wrong_prefix_str0[] = "10.11.12.245/45";
  static inline const char wrong_prefix_str1[] = "10.400.12.13/8";
  static inline const char wrong_prefix_str2[] = "2001:db8:1::/640";
  static inline const char wrong_prefix_str3[] = "20011::db8:1::/16";
  static inline const char wrong_prefix_str4[] = "2001::db8:1::fffff/96";

  PrefixTest() = default;

  ~PrefixTest() override = default;

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  void SetUp() override {
    // Code here will be called immediately after the constructor (right
    // before each test).
  }

  void TearDown() override {
    // Code here will be called immediately after each test (right
    // before the destructor).
  }
};

TEST_F(PrefixTest, ConstructorRightString) {
  // Create empty prefix
  Prefix p;

  // Create prefix from string
  Prefix p0(prefix_str0);
  // Reconstruct string and check it is equal to original address
  std::string network = p0.getNetwork();
  std::uint16_t prefix_length = p0.getPrefixLength();
  EXPECT_THAT(network + "/" + std::to_string(prefix_length),
              ::testing::StrEq(prefix_str0));

  // Create prefix from string
  Prefix p1(prefix_str1);
  // Reconstruct string and check it is equal to original address
  network = p1.getNetwork();
  prefix_length = p1.getPrefixLength();
  EXPECT_THAT(network + "/" + std::to_string(prefix_length),
              ::testing::StrEq(prefix_str1));

  // Create prefix from string
  Prefix p2(prefix_str2);
  // Reconstruct string and check it is equal to original address
  network = p2.getNetwork();
  prefix_length = p2.getPrefixLength();
  EXPECT_THAT(network + "/" + std::to_string(prefix_length),
              ::testing::StrEq(prefix_str2));

  // Create prefix from string
  Prefix p3(prefix_str3);
  // Reconstruct string and check it is equal to original address
  network = p3.getNetwork();
  prefix_length = p3.getPrefixLength();
  EXPECT_THAT(network + "/" + std::to_string(prefix_length),
              ::testing::StrEq(prefix_str3));

  // Create prefix from string and prefix length
  Prefix p4("2001::1234", 66);
  // Reconstruct string and check it is equal to original address
  network = p4.getNetwork();
  prefix_length = p4.getPrefixLength();
  auto af = p4.getAddressFamily();
  EXPECT_THAT(network, ::testing::StrEq("2001::1234"));
  EXPECT_THAT(prefix_length, ::testing::Eq(66));
  EXPECT_THAT(af, ::testing::Eq(AF_INET6));
}

TEST_F(PrefixTest, ConstructorWrongString) {
  try {
    Prefix p0(wrong_prefix_str0);
    FAIL() << "Expected exception";
  } catch (const errors::InvalidIpAddressException &) {
    // Expected exception
  }

  try {
    Prefix p1(wrong_prefix_str1);
    FAIL() << "Expected exception";
  } catch (const errors::InvalidIpAddressException &) {
    // Expected exception
  }

  try {
    Prefix p2(wrong_prefix_str2);
    FAIL() << "Expected exception";
  } catch (const errors::InvalidIpAddressException &) {
    // Expected exception
  }

  try {
    Prefix p3(wrong_prefix_str3);
    FAIL() << "Expected exception";
  } catch (const errors::InvalidIpAddressException &) {
    // Expected exception
  }

  try {
    Prefix p4(wrong_prefix_str4);
    FAIL() << "Expected exception";
  } catch (const errors::InvalidIpAddressException &) {
    // Expected exception
  }
}

TEST_F(PrefixTest, Comparison) {
  Prefix p0(prefix_str0);
  Prefix p1(prefix_str1);

  // Expect they are different
  EXPECT_THAT(p0, ::testing::Ne(p1));

  auto p2 = p1;
  // Expect they are equal
  EXPECT_THAT(p1, ::testing::Eq(p2));
}

TEST_F(PrefixTest, ToSockAddress) {
  Prefix p0(prefix_str3);

  auto ret = p0.toSockaddr();
  auto sockaddr = reinterpret_cast<sockaddr_in *>(ret.get());

  EXPECT_THAT(sockaddr->sin_family, ::testing::Eq(AF_INET));
  EXPECT_THAT(sockaddr->sin_addr.s_addr, portability::host_to_net(0x0a0b0cf5));
}

TEST_F(PrefixTest, GetPrefixLength) {
  Prefix p0(prefix_str3);
  EXPECT_THAT(p0.getPrefixLength(), ::testing::Eq(27));
}

TEST_F(PrefixTest, SetPrefixLength) {
  Prefix p0(prefix_str3);
  EXPECT_THAT(p0.getPrefixLength(), ::testing::Eq(27));
  p0.setPrefixLength(20);
  EXPECT_THAT(p0.getPrefixLength(), ::testing::Eq(20));

  try {
    p0.setPrefixLength(33);
    FAIL() << "Expected exception";
  } catch ([[maybe_unused]] const errors::InvalidIpAddressException &) {
    // Expected exception
  }
}

TEST_F(PrefixTest, SetGetNetwork) {
  Prefix p0(prefix_str0);
  EXPECT_THAT(p0.getPrefixLength(), ::testing::Eq(64));
  p0.setNetwork("b001::1234");
  EXPECT_THAT(p0.getNetwork(), ::testing::StrEq("b001::1234"));
  EXPECT_THAT(p0.getPrefixLength(), ::testing::Eq(64));
}

TEST_F(PrefixTest, Contains) {
  // IPv6 prefix
  Prefix p0(prefix_str0);
  ip_address_t ip0, ip1;

  ip_address_pton("2001:db8:1::1234", &ip0);
  ip_address_pton("2001:db9:1::1234", &ip1);

  EXPECT_TRUE(p0.contains(ip0));
  EXPECT_FALSE(p0.contains(ip1));

  Prefix p1(prefix_str1);
  ip_address_pton("10.11.12.12", &ip0);
  ip_address_pton("10.12.12.13", &ip1);

  EXPECT_TRUE(p1.contains(ip0));
  EXPECT_FALSE(p1.contains(ip1));

  Prefix p2(prefix_str2);
  ip_address_pton("2001:db8:1::dbca", &ip0);
  ip_address_pton("10.12.12.12", &ip1);

  EXPECT_TRUE(p2.contains(ip0));
  EXPECT_FALSE(p2.contains(ip1));

  Prefix p3(prefix_str3);
  ip_address_pton("10.11.12.245", &ip0);
  ip_address_pton("10.11.12.1", &ip1);

  EXPECT_TRUE(p3.contains(ip0));
  EXPECT_FALSE(p3.contains(ip1));

  // Corner cases
  Prefix p4("::/0");
  ip_address_pton("7001:db8:1::1234", &ip0);
  ip_address_pton("8001:db8:1::1234", &ip1);

  EXPECT_TRUE(p4.contains(ip0));
  EXPECT_TRUE(p4.contains(ip1));

  // Corner cases
  Prefix p5("b001:a:b:c:d:e:f:1/128");
  ip_address_pton("b001:a:b:c:d:e:f:1", &ip0);
  ip_address_pton("b001:a:b:c:d:e:f:2", &ip1);

  EXPECT_TRUE(p5.contains(ip0));
  EXPECT_FALSE(p5.contains(ip1));
}

TEST_F(PrefixTest, GetAddressFamily) {
  Prefix p0(prefix_str0);
  auto af = p0.getAddressFamily();
  EXPECT_THAT(af, ::testing::Eq(AF_INET6));

  Prefix p1(prefix_str1);
  af = p1.getAddressFamily();
  EXPECT_THAT(af, ::testing::Eq(AF_INET));
}

TEST_F(PrefixTest, MakeName) {
  Prefix p0(prefix_str0);
  auto name0 = p0.makeName();
  EXPECT_THAT(name0.toString(), ::testing::StrEq("2001:db8:1::|0"));

  Prefix p1(prefix_str1);
  auto name1 = p1.makeName();
  EXPECT_THAT(name1.toString(), ::testing::StrEq("10.11.12.0|0"));

  Prefix p2(prefix_str2);
  auto name2 = p2.makeName();
  EXPECT_THAT(name2.toString(), ::testing::StrEq("2001:db8:1::|0"));

  Prefix p3(prefix_str3);
  auto name3 = p3.makeName();
  EXPECT_THAT(name3.toString(), ::testing::StrEq("10.11.12.224|0"));

  Prefix p4("b001:a:b:c:d:e:f:1/128");
  auto name4 = p4.makeName();
  EXPECT_THAT(name4.toString(), ::testing::StrEq("b001:a:b:c:d:e:f:1|0"));
}

TEST_F(PrefixTest, MakeRandomName) {
  Prefix p0(prefix_str0);
  auto name0 = p0.makeRandomName();
  auto name1 = p0.makeRandomName();
  auto name2 = p0.makeRandomName();
  auto name3 = p0.makeRandomName();

  EXPECT_THAT(name0, ::testing::Not(::testing::Eq(name1)));
  EXPECT_THAT(name0, ::testing::Not(::testing::Eq(name2)));
  EXPECT_THAT(name0, ::testing::Not(::testing::Eq(name3)));
  EXPECT_THAT(name1, ::testing::Not(::testing::Eq(name2)));
  EXPECT_THAT(name1, ::testing::Not(::testing::Eq(name3)));
  EXPECT_THAT(name2, ::testing::Not(::testing::Eq(name3)));

  // Corner case
  Prefix p2("b001:a:b:c:d:e:f:1/128");
  name0 = p2.makeRandomName();
  name1 = p2.makeRandomName();
  name2 = p2.makeRandomName();
  name3 = p2.makeRandomName();

  EXPECT_THAT(name0, ::testing::Eq(name1));
  EXPECT_THAT(name0, ::testing::Eq(name2));
  EXPECT_THAT(name0, ::testing::Eq(name3));
  EXPECT_THAT(name1, ::testing::Eq(name2));
  EXPECT_THAT(name1, ::testing::Eq(name3));
  EXPECT_THAT(name2, ::testing::Eq(name3));
}

TEST_F(PrefixTest, MakeNameWithIndex) {
  Prefix p0(prefix_str0);
  auto name0 = p0.makeNameWithIndex(0);
  EXPECT_THAT(name0.toString(), ::testing::StrEq("2001:db8:1::|0"));
  auto name1 = p0.makeNameWithIndex(1);
  EXPECT_THAT(name1.toString(), ::testing::StrEq("2001:db8:1::1|0"));
  auto name2 = p0.makeNameWithIndex(2);
  EXPECT_THAT(name2.toString(), ::testing::StrEq("2001:db8:1::2|0"));
  auto name3 = p0.makeNameWithIndex(3);
  EXPECT_THAT(name3.toString(), ::testing::StrEq("2001:db8:1::3|0"));

  Prefix p1(prefix_str1);
  name0 = p1.makeNameWithIndex(0);
  EXPECT_THAT(name0.toString(), ::testing::StrEq("10.11.12.0|0"));
  name1 = p1.makeNameWithIndex(1);
  EXPECT_THAT(name1.toString(), ::testing::StrEq("10.11.12.1|0"));
  name2 = p1.makeNameWithIndex(2);
  EXPECT_THAT(name2.toString(), ::testing::StrEq("10.11.12.2|0"));
  name3 = p1.makeNameWithIndex(3);
  EXPECT_THAT(name3.toString(), ::testing::StrEq("10.11.12.3|0"));

  // Test truncation
  Prefix p2("b001::/96");
  name0 = p2.makeNameWithIndex(0xffffffffffffffff);
  EXPECT_THAT(name0.toString(), ::testing::StrEq("b001::ffff:ffff|0"));
}

}  // namespace

}  // namespace core
}  // namespace transport