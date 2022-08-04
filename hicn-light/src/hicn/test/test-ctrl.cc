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

extern "C" {
#include <hicn/util/log.h>
#include <hicn/ctrl.h>
#include <hicn/ctrl/parse.h>
#include <hicn/ctrl/route.h>
#include <hicn/util/sstrncpy.h>
}

class CtrlTest : public ::testing::Test {
 protected:
  CtrlTest() {
    log_conf.log_level = LOG_INFO;
    s_ = hc_sock_create_forwarder(FORWARDER_TYPE_HICNLIGHT);
  }
  virtual ~CtrlTest() { hc_sock_free(s_); }

  hc_sock_t *s_ = nullptr;
  hc_command_t command_ = {};
};

/**
 * The parse() function is used to easily create the command.
 * Here we test the serialization of the commands i.e. from command
 * to message sent to the forwarder.
 */
#if 0
TEST_F(CtrlTest, AddValidListener) {
  std::string cmd = "add listener udp udp0 10.0.0.1 9695 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  hc_result_t *result = hc_listener_create_conf(s_, &command_.object.listener);
  bool success = hc_result_get_success(s_, result);
  EXPECT_TRUE(success);
}

TEST_F(CtrlTest, AddListenerInvalidProtocol) {
  // Set invalid protocol (icmp)
  std::string cmd = "add listener icmp udp0 10.0.0.1 9696 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  hc_result_t *result = hc_listener_create_conf(s_, &command_.object.listener);
  bool success = hc_result_get_success(s_, result);
  EXPECT_FALSE(success);
}

TEST_F(CtrlTest, AddListenerInvalidLocalPort) {
  std::string cmd = "add listener udp udp0 10.0.0.1 9695 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  // Override with invalid port
  command_.object.listener.local_port = 0;

  hc_result_t *result = hc_listener_create_conf(s_, &command_.object.listener);
  bool success = hc_result_get_success(s_, result);
  EXPECT_FALSE(success);
}

TEST_F(CtrlTest, AddListenerInvalidLocalAddress) {
  std::string cmd = "add listener udp udp0 10.0.0.1 9695 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  // Override with invalid family
  command_.object.listener.family = -1;

  hc_result_t *result = hc_listener_create_conf(s_, &command_.object.listener);
  bool success = hc_result_get_success(s_, result);
  EXPECT_EQ(success, false);
}

TEST_F(CtrlTest, AddListenerEmptyLocalAddress) {
  std::string cmd = "add listener udp udp0 10.0.0.1 9695 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  // Override with invalid address
  command_.object.listener.local_addr = IP_ADDRESS_EMPTY;

  hc_result_t *result = hc_listener_create_conf(s_, &command_.object.listener);
  bool success = hc_result_get_success(s_, result);
  EXPECT_FALSE(success);
}

TEST_F(CtrlTest, AddListenerInvalidSymbolicName) {
  std::string cmd = "add listener udp 0udp 10.0.0.1 9695 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  hc_result_t *result = hc_listener_create_conf(s_, &command_.object.listener);
  bool success = hc_result_get_success(s_, result);
  EXPECT_FALSE(success);
}

TEST_F(CtrlTest, AddListenerInvalidSymbolicName2) {
  std::string cmd = "add listener udp udp! 10.0.0.1 9695 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  hc_result_t *result = hc_listener_create_conf(s_, &command_.object.listener);
  bool success = hc_result_get_success(s_, result);
  EXPECT_FALSE(success);
}

TEST_F(CtrlTest, AddListenerInvalidInterfaceName) {
  std::string cmd = "add listener udp udp0 10.0.0.1 9695 eth/0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  hc_result_t *result = hc_listener_create_conf(s_, &command_.object.listener);
  bool success = hc_result_get_success(s_, result);
  EXPECT_FALSE(success);
}

TEST_F(CtrlTest, AddValidRoute) {
  std::string cmd = "add route conn0 c001::/64 1";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  hc_result_t *result = hc_route_create_conf(s_, &command_.object.route);
  bool success = hc_result_get_success(s_, result);
  EXPECT_TRUE(success);
}

TEST_F(CtrlTest, AddRouteInvalidLength) {
  std::string cmd = "add route conn0 c001::/64 1";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  // Override with invalid prfix len
  command_.object.route.len = MAX_IPV6_PREFIX_LEN + 1;

  hc_result_t *result = hc_route_create_conf(s_, &command_.object.route);
  bool success = hc_result_get_success(s_, result);
  EXPECT_FALSE(success);
}

TEST_F(CtrlTest, AddRouteInvalidCost) {
  std::string cmd = "add route conn0 c001::/64 1";
  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);

  // Override with invalid cost
  command_.object.route.cost = MAX_ROUTE_COST + 1;

  hc_result_t *result = hc_route_create_conf(s_, &command_.object.route);
  bool success = hc_result_get_success(s_, result);
  EXPECT_FALSE(success);

  // Override with invalid cost
  command_.object.route.cost = MIN_ROUTE_COST - 1;

  result = hc_route_create_conf(s_, &command_.object.route);
  success = hc_result_get_success(s_, result);
  EXPECT_FALSE(success);
}

TEST_F(CtrlTest, RouteNameOrID) {
  hc_route_t route = {
      .face_id = (face_id_t)INVALID_FACE_ID,
      .family = AF_INET6,
      .remote_addr = IPV6_LOOPBACK,
      .len = 64,
      .cost = 1,
  };

  // At least one between name (symbolic or ID) and face_id
  // should be set to make the route valid

  // Valid name (symbolic)
  snprintf(route.name, SYMBOLIC_NAME_LEN, "%s", "test");
  EXPECT_EQ(hc_route_validate(&route), 0);

  // Valid name (ID)
  snprintf(route.name, SYMBOLIC_NAME_LEN, "%s", "conn0");
  EXPECT_EQ(hc_route_validate(&route), 0);

  // Valid face_id
  route.face_id = 1;
  snprintf(route.name, SYMBOLIC_NAME_LEN, "%s", "");
  EXPECT_EQ(hc_route_validate(&route), 0);

  // Invalid name stating with number
  // (face_id is only checked if empty name)
  route.face_id = 1;
  snprintf(route.name, SYMBOLIC_NAME_LEN, "%s", "1test");
  EXPECT_EQ(hc_route_validate(&route), -1);
}
#endif
