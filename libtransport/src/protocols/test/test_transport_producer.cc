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

#include "../socket_producer.h"
#include "literals.h"

#include <test.h>
#include <random>

namespace transport {

namespace protocol {

namespace {
// The fixture for testing class Foo.
class ProducerTest : public ::testing::Test {
 protected:
  ProducerTest() : name_("b001::123|321"), producer_(io_service_) {
    // You can do set-up work for each test here.
  }

  virtual ~ProducerTest() {
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
  asio::io_service io_service_;
  ProducerSocket producer_;
};

}  // namespace

// Tests that the Foo::Bar() method does Abc.
TEST_F(ProducerTest, ProduceContent) {
  std::string content(250000, '?');

  producer_.registerPrefix(Prefix("b001::/64"));
  producer_.produce(name_, reinterpret_cast<const uint8_t *>(content.data()),
                    content.size(), true);
  producer_.setSocketOption(GeneralTransportOptions::CONTENT_OBJECT_EXPIRY_TIME,
                            500000000_U32);
  producer_.attach();
  producer_.serveForever();
}

}  // namespace protocol

}  // namespace transport

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}