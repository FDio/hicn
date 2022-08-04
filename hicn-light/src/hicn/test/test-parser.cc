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
#include <hicn/ctrl/parse.h>
}

class ParserTest : public ::testing::Test {
 protected:
  ParserTest() { log_conf.log_level = LOG_INFO; }
  virtual ~ParserTest() {}

  hc_command_t command_ = {};
};

TEST_F(ParserTest, AddValidListener) {
  std::string cmd = "add listener udp udp0 10.0.0.1 9695 eth0";

  ASSERT_EQ(parse(cmd.c_str(), &command_), 0);
  EXPECT_EQ(command_.object.listener.type, FACE_TYPE_UDP_LISTENER);
  EXPECT_EQ(std::string(command_.object.listener.name), "udp0");
  EXPECT_EQ(command_.object.listener.family, AF_INET);
  EXPECT_EQ(command_.object.listener.local_port, 9695);
  EXPECT_EQ(std::string(command_.object.listener.interface_name), "eth0");
}

TEST_F(ParserTest, AddListenerSymbolicOverflow) {
  std::string cmd =
      "add listener udp super-long-symbolic-name 10.0.0.1 9696 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), -1);
}

TEST_F(ParserTest, AddListenerInvalidAddress) {
  std::string cmd = "add listener udp udp0 10.0.0.0.1 9696 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), -1);
}

TEST_F(ParserTest, AddListenerInvalidAddressString) {
  std::string cmd = "add listener udp udp0 invalid-addr 9696 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), -1);
}

TEST_F(ParserTest, AddListenerInvalidPortOutsideRange) {
  std::string cmd = "add listener udp udp0 10.0.0.1 0 eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), -1);
}

TEST_F(ParserTest, AddListenerInvalidPortString) {
  std::string cmd = "add listener udp udp0 10.0.0.1 invalid-port eth0";
  ASSERT_EQ(parse(cmd.c_str(), &command_), -1);
}

TEST_F(ParserTest, UnknownCommnad) {
  std::string cmd = "add face";
  ASSERT_EQ(parse(cmd.c_str(), &command_), -1);
}
