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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <hicn/transport/interfaces/global_conf_interface.h>
#include <hicn/transport/interfaces/socket_consumer.h>
#include <hicn/transport/interfaces/socket_options_keys.h>
#include <hicn/transport/interfaces/socket_producer.h>

namespace transport {
namespace interface {

class SessionsTest : public ::testing::Test {
 protected:
  static inline const std::size_t default_size = 2048;
  static inline const std::size_t default_n_buffer = 1024;

  // Get fixed block allocator_ of 1024 buffers of size 2048 bytes
  SessionsTest() {
    // You can do set-up work for each test here.
    // Set io_module to local forwarder with no external connections
    global_config::IoModuleConfiguration config;
    config.name = "forwarder_module";
    config.set();
  }

  virtual ~SessionsTest() {
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

  std::vector<ConsumerSocket> consumers_;
  std::vector<ProducerSocket> producers_;
};

TEST_F(SessionsTest, SessionAllocations) {
  // Create 1000 consumer sockets and 1000 producer sockets
  int cprotocol = TransportProtocolAlgorithms::RAAQM;
  int pprotocol = ProductionProtocolAlgorithms::BYTE_STREAM;
  int offset = 0;

  for (int i = 0; i < 1000; i++) {
    auto &c = consumers_.emplace_back(cprotocol + (offset % 3));
    auto &p = producers_.emplace_back(pprotocol + (offset % 2));
    c.connect();
    p.connect();
    offset++;
  }
}

}  // namespace interface
}  // namespace transport