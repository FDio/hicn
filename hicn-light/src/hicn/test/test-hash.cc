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

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
// #include <hicn/transport/utils/hash.h>

extern "C" {
#include <hicn/base/hash.h>
#include <hicn/core/address_pair.h>
#include <hicn/core/listener.h>
}

TEST(HashTest, MultipleHashesForSameAddrPair) {
  address_pair_t pair =
      address_pair_factory(_ADDRESS4_LOCALHOST(1), _ADDRESS4_LOCALHOST(2));

  unsigned h1 = hash_struct(&pair);
  unsigned h2 = hash_struct(&pair);
  EXPECT_EQ(h1, h2);
}

TEST(HashTest, SameAddrPairs) {
  address_pair_t pair1 =
      address_pair_factory(_ADDRESS4_LOCALHOST(1), _ADDRESS4_LOCALHOST(2));
  address_pair_t pair2 = pair1;

  unsigned h1 = hash_struct(&pair1);
  unsigned h2 = hash_struct(&pair2);
  EXPECT_EQ(h1, h2);
}

TEST(HashTest, DifferentAddrPairs) {
  address_pair_t pair1 =
      address_pair_factory(_ADDRESS4_LOCALHOST(1), _ADDRESS4_LOCALHOST(2));

  address_pair_t pair2 =
      address_pair_factory(_ADDRESS4_LOCALHOST(3), _ADDRESS4_LOCALHOST(4));

  unsigned h1 = hash_struct(&pair1);
  unsigned h2 = hash_struct(&pair2);
  EXPECT_NE(h1, h2);
}

TEST(HashTest, SameLocalDifferentRemote) {
  address_pair_t pair1 =
      address_pair_factory(_ADDRESS4_LOCALHOST(1), _ADDRESS4_LOCALHOST(2));

  address_pair_t pair2 =
      address_pair_factory(_ADDRESS4_LOCALHOST(1), _ADDRESS4_LOCALHOST(4));

  unsigned h1 = hash_struct(&pair1);
  unsigned h2 = hash_struct(&pair2);
  EXPECT_NE(h1, h2);
}

TEST(HashTest, SameRemoteDifferentLocal) {
  address_pair_t pair1 =
      address_pair_factory(_ADDRESS4_LOCALHOST(1), _ADDRESS4_LOCALHOST(2));

  address_pair_t pair2 =
      address_pair_factory(_ADDRESS4_LOCALHOST(3), _ADDRESS4_LOCALHOST(2));

  unsigned h1 = hash_struct(&pair1);
  unsigned h2 = hash_struct(&pair2);
  EXPECT_NE(h1, h2);
}

TEST(HashTest, SameAddresses) {
  address_t addr1 = _ADDRESS4_LOCALHOST(1);
  address_t addr2 = _ADDRESS4_LOCALHOST(1);

  unsigned h1 = hash_struct(&addr1);
  unsigned h2 = hash_struct(&addr2);

  EXPECT_EQ(h1, h2);
}

TEST(HashTest, SameListenerKeys) {
  listener_key_t key1 =
      listener_key_factory(_ADDRESS4_LOCALHOST(1), FACE_TYPE_UDP_LISTENER);
  listener_key_t key2 =
      listener_key_factory(_ADDRESS4_LOCALHOST(1), FACE_TYPE_UDP_LISTENER);

  unsigned h1 = hash_struct(&key1);
  unsigned h2 = hash_struct(&key2);

  EXPECT_EQ(h1, h2);
}

TEST(HashTest, Collisions) {
  uint32_t init_val = 2166136261UL;
  (void)init_val;

  std::map<u32, uint32_t> hashes;
  for (int i = 0; i < 50000; i++) {
    uint32_t seg = i;
    // u32 h = utils::hash::fnv32_buf (&seg, sizeof (seg));
    // u32 h = cumulative_hash32 (&seg, sizeof (seg), init_val);
    u32 h = hash(&seg, sizeof(seg));
    EXPECT_FALSE(hashes.find(h) != hashes.end()) << seg << " - " << hashes[h];
    hashes[h] = seg;
  }
}