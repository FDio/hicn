/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
#define WITH_TESTS
#include <hicn/util/ip_address.h>
#include <hicn/config/configuration.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/fib.h>
}

/*
 * TODO
 * - test max_size
 */

#define DEFAULT_SIZE 10
#define ARRAY_SIZE(a) ((sizeof(a) / sizeof(*(a))))

class FibTest : public ::testing::Test {
 protected:
  FibTest() { fib = fib_create(NULL); }
  virtual ~FibTest() { fib_free(fib); }

  configuration_t *configuration;
  forwarder_t *forwarder;
  fib_t *fib;
};

fib_entry_t *_fib_add_prefix(fib_t *fib, const hicn_prefix_t *prefix) {
  fib_entry_t *entry =
      fib_entry_create(prefix, STRATEGY_TYPE_UNDEFINED, NULL, NULL);
  fib_add(fib, entry);
  return entry;
}

#if 0
static const hicn_prefix_t p0010 = (hicn_prefix_t){
    .name = {.v6 = {.as_u64 = {0x1122334455667788, 0x9900aabbccddeeff}}},
    .len = 4};
#endif

#define HICN_PREFIX(P, STR)                      \
  hicn_prefix_t P;                               \
  hicn_ip_prefix_t _##P;                         \
  EXPECT_EQ(hicn_ip_prefix_pton(STR, &_##P), 0); \
  EXPECT_EQ(hicn_prefix_create_from_ip_prefix(&_##P, &P), 0);

/* TEST: Fib allocation and initialization */
TEST_F(FibTest, FibAddOne) {
  /* Empty fib should be valid */

  HICN_PREFIX(pfx, "1122:3344:5566:7788:9900:aabb:ccdd:eeff/4");

  const hicn_prefix_t *empty_prefix_array[] = {};
  bool empty_used_array[] = {};
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, empty_prefix_array, empty_used_array));

  const hicn_prefix_t *prefix_array[] = {&pfx};
  bool used_array[] = {true};

  for (unsigned i = 0; i < ARRAY_SIZE(prefix_array); i++) {
    if (!used_array[i]) continue;
    _fib_add_prefix(fib, prefix_array[i]);
  }

  fib_dump(fib);

  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array, used_array));

  /* Check that free indices and bitmaps are correctly updated */
}

TEST_F(FibTest, FibAddTwo) {
  HICN_PREFIX(b001, "b001::/64");
  HICN_PREFIX(c001, "c001::/64");
  HICN_PREFIX(inner_8000_1, "8000::/1");

  const hicn_prefix_t *prefix_array[] = {&b001, &inner_8000_1, &c001};
  bool used_array[] = {true, false, true};

  _fib_add_prefix(fib, &b001);
  _fib_add_prefix(fib, &c001);

  fib_dump(fib);

  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array, used_array));
}

TEST_F(FibTest, FibAddFive) {
  HICN_PREFIX(b002, "b002::/64");
  HICN_PREFIX(b002_abcd_0, "b002::abcd:0:0:0/128");
  HICN_PREFIX(b002_2, "b002::2/128");
  HICN_PREFIX(b002_abcd_1, "b002::abcd:0:0:1/128");
  HICN_PREFIX(b002_3, "b002::3/128");
  HICN_PREFIX(inner_b002_2, "b002::2/127");
  HICN_PREFIX(inner_b002_abcd_0, "b002::abcd:0:0:0/127");

  const hicn_prefix_t *prefix_array[] = {
      &b002_2,      &inner_b002_2,      &b002_3,     &b002,
      &b002_abcd_0, &inner_b002_abcd_0, &b002_abcd_1};
  bool used_array[] = {true, false, true, true, true, false, true};

  _fib_add_prefix(fib, &b002);
  _fib_add_prefix(fib, &b002_abcd_0);
  _fib_add_prefix(fib, &b002_2);
  _fib_add_prefix(fib, &b002_abcd_1);
  _fib_add_prefix(fib, &b002_3);

  fib_dump(fib);

  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array, used_array));
}

TEST_F(FibTest, FibAddRemove) {
  HICN_PREFIX(b002_64, "b002::/64");
  HICN_PREFIX(b002_128, "b002::/128");

  const hicn_prefix_t *prefix_array_1[] = {&b002_128};
  bool used_array_1[] = {true};
  const hicn_prefix_t *prefix_array_2[] = {};
  bool used_array_2[] = {};
  const hicn_prefix_t *prefix_array_3[] = {&b002_64};
  bool used_array_3[] = {true};

  fib_entry_t *entry = _fib_add_prefix(fib, &b002_128);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array_1, used_array_1));

  fib_remove_entry(fib, entry);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array_2, used_array_2));

  entry = _fib_add_prefix(fib, &b002_64);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array_3, used_array_3));
}

TEST_F(FibTest, FibAddNested) {
  HICN_PREFIX(b002_64, "b002::/64");
  HICN_PREFIX(b002_128, "b002::/128");

  const hicn_prefix_t *prefix_array_1[] = {&b002_128};
  bool used_array_1[] = {true};
  const hicn_prefix_t *prefix_array_2[] = {&b002_128, &b002_64};
  bool used_array_2[] = {true, true};

  _fib_add_prefix(fib, &b002_128);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array_1, used_array_1));

  _fib_add_prefix(fib, &b002_64);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array_2, used_array_2));
}
