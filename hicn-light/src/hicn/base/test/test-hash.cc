/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>

extern "C" {
#include <hicn/base/hash.h>
#include <hicn/core/address_pair.h>
}

TEST(HashTest, MultipleHashesForSameAddrPair)
{
  address_pair_t pair = {
    .local = _ADDRESS4_LOCALHOST(1),
    .remote = _ADDRESS4_LOCALHOST(2)
  };

  unsigned h1 = hash_struct(&pair);
  unsigned h2 = hash_struct(&pair);
  EXPECT_EQ(h1, h2);
}

TEST(HashTest, SameAddrPairs)
{
  address_pair_t pair1 = {
    .local = _ADDRESS4_LOCALHOST(1),
    .remote = _ADDRESS4_LOCALHOST(2)
  };
  address_pair_t pair2 = pair1;

  unsigned h1 = hash_struct(&pair1);
  unsigned h2 = hash_struct(&pair2);
  EXPECT_EQ(h1, h2);
}

TEST(HashTest, DifferentAddrPairs)
{
  address_pair_t pair1 = {
    .local = _ADDRESS4_LOCALHOST(1),
    .remote = _ADDRESS4_LOCALHOST(2)
  };

  address_pair_t pair2 = {
    .local = _ADDRESS4_LOCALHOST(3),
    .remote = _ADDRESS4_LOCALHOST(4)
  };

  unsigned h1 = hash_struct(&pair1);
  unsigned h2 = hash_struct(&pair2);
  EXPECT_NE(h1, h2);
}

TEST(HashTest, SameLocalDifferentRemote)
{
  address_pair_t pair1 = {
    .local = _ADDRESS4_LOCALHOST(1),
    .remote = _ADDRESS4_LOCALHOST(2)
  };

  address_pair_t pair2 = {
    .local = _ADDRESS4_LOCALHOST(1),
    .remote = _ADDRESS4_LOCALHOST(4)
  };

  unsigned h1 = hash_struct(&pair1);
  unsigned h2 = hash_struct(&pair2);
  EXPECT_NE(h1, h2);
}

TEST(HashTest, SameRemoteDifferentLocal)
{
  address_pair_t pair1 = {
    .local = _ADDRESS4_LOCALHOST(1),
    .remote = _ADDRESS4_LOCALHOST(2)
  };

  address_pair_t pair2 = {
    .local = _ADDRESS4_LOCALHOST(3),
    .remote = _ADDRESS4_LOCALHOST(2)
  };

  unsigned h1 = hash_struct(&pair1);
  unsigned h2 = hash_struct(&pair2);
  EXPECT_NE(h1, h2);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
