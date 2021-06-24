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

#include <random>

#include "hicn/transport/interfaces/socket_producer.h"

namespace transport {

namespace interface {

namespace {
// The fixture for testing class Foo.
class ProducerTest : public ::testing::Test {
 protected:
  ProducerTest() : name_("b001::123|321"), producer_() {
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
  ProducerSocket producer_;
};

}  // namespace

TEST_F(ProducerTest, ProduceContent) { ASSERT_TRUE(true); }

}  // namespace interface

}  // namespace transport

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}