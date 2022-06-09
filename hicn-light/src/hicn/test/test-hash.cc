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
#include <unordered_set>
#include <hicn/test/test-utils.h>

extern "C" {
#include <hicn/util/hash.h>
#include <hicn/core/address_pair.h>
#include <hicn/core/listener.h>
}

static constexpr uint32_t init_val = 2166136261UL;
static constexpr int N_HASHES = 50000;

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
  std::unordered_set<uint32_t> hashes;
  int n_collisions = 0;
  for (int i = 0; i < 50000; i++) {
    uint32_t seg = i;
    // u32 h = utils::hash::fnv32_buf(&seg, sizeof(seg));
    // u32 h = cumulative_hash32(&seg, sizeof(uint32_t), init_val);
    u32 h = hash(&seg, sizeof(seg));

    if (hashes.find(h) != hashes.end()) n_collisions++;
    hashes.insert(h);
  }
  EXPECT_EQ(n_collisions, 0);
}

/*** Compare FNV with Jenkins ***/

typedef struct {
  uint32_t data[6];
} small_struct_t;  // Same size as 'NameBitvector'

typedef struct {
  uint64_t data[32];
} big_struct_t;  // Same size as 'address_pair_t'

TEST(HashTest, PerformanceComparisonSmallStruct) {
  small_struct_t small_struct;

  // FNV
  auto time_fnv = get_execution_time([&]() {
    for (int i = 0; i < N_HASHES; i++) {
      small_struct.data[0] = i;
      cumulative_hash32(&small_struct, sizeof(small_struct_t), init_val);
    }
  });

  // Jenkins
  auto time_jenkins = get_execution_time([&]() {
    for (int i = 0; i < N_HASHES; i++) {
      small_struct.data[0] = i;
      hash(&small_struct, sizeof(small_struct_t));
    }
  });

  std::cout << "Small struct (size = " << sizeof(small_struct_t) << " bytes)\n";
  std::cout << "FNV: " << time_fnv << "ms\n";
  std::cout << "Jenkins: " << time_jenkins << "ms\n";
}

TEST(HashTest, PerformanceComparisonBigStruct) {
  big_struct_t big_struct;

  // FNV
  auto time_fnv = get_execution_time([&]() {
    for (int i = 0; i < N_HASHES; i++) {
      big_struct.data[0] = i;
      cumulative_hash32(&big_struct, sizeof(big_struct_t), init_val);
    }
  });

  // Jenkins
  auto time_jenkins = get_execution_time([&]() {
    for (int i = 0; i < N_HASHES; i++) {
      big_struct.data[0] = i;
      hash(&big_struct, sizeof(big_struct_t));
    }
  });

  std::cout << "Big struct (size = " << sizeof(big_struct_t) << " bytes)\n";
  std::cout << "FNV: " << time_fnv << "ms\n";
  std::cout << "Jenkins: " << time_jenkins << "ms\n";
}

TEST(HashTest, CollisionsComparison) {
  small_struct_t small_struct = {0};
  std::unordered_set<uint32_t> hashes;
  int n_collisions_fnv = 0, n_collisions_jenkins = 0, n_collisions_murmur = 0,
      n_collisions_xxhash = 0;

  // FNV
  for (int i = 0; i < 10 * N_HASHES; i++) {
    small_struct.data[0] = i;
    uint32_t h =
        cumulative_hash32(&small_struct, sizeof(small_struct_t), init_val);

    if (hashes.find(h) != hashes.end()) n_collisions_fnv++;
    hashes.insert(h);
  }

  hashes.clear();

  // Jenkins
  for (int i = 0; i < 10 * N_HASHES; i++) {
    small_struct.data[0] = i;
    uint32_t h = hash(&small_struct, sizeof(small_struct_t));

    if (hashes.find(h) != hashes.end()) n_collisions_jenkins++;
    hashes.insert(h);
  }

  std::cout << "Small struct (size = " << sizeof(small_struct_t) << " bytes)\n";
  std::cout << "FNV: " << n_collisions_fnv << " collision/s\n";
  std::cout << "Jenkins: " << n_collisions_jenkins << " collision/s\n";
}