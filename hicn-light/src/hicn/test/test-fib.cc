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
#include <vector>

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

fib_entry_t *_fib_add_prefix(fib_t *fib, const hicn_prefix_t *prefix,
                             std::vector<uint32_t> &nexthops) {
  fib_entry_t *entry =
      fib_entry_create(prefix, STRATEGY_TYPE_UNDEFINED, NULL, NULL);
  for (size_t i = 0; i < nexthops.size(); i++)
    fib_entry_nexthops_add(entry, nexthops[i]);
  fib_add(fib, entry);
  return entry;
}

int compare_str_prefix_to_prefix(char *p1, hicn_prefix_t *p2) {
  char prefix_s[MAXSZ_IP_PREFIX];
  hicn_ip_prefix_t ipp;
  hicn_prefix_get_ip_prefix(p2, &ipp);
  hicn_ip_prefix_snprintf(prefix_s, MAXSZ_IP_PREFIX,
                          (const hicn_ip_prefix_t *)&ipp);
  return strcmp(prefix_s, p1);
}

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

  std::vector<uint32_t> empty_nexthop;
  for (unsigned i = 0; i < ARRAY_SIZE(prefix_array); i++) {
    if (!used_array[i]) continue;
    _fib_add_prefix(fib, prefix_array[i], empty_nexthop);
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

  std::vector<uint32_t> empty_nexthop;
  _fib_add_prefix(fib, &b001, empty_nexthop);
  _fib_add_prefix(fib, &c001, empty_nexthop);

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

  std::vector<uint32_t> empty_nexthop;
  _fib_add_prefix(fib, &b002, empty_nexthop);
  _fib_add_prefix(fib, &b002_abcd_0, empty_nexthop);
  _fib_add_prefix(fib, &b002_2, empty_nexthop);
  _fib_add_prefix(fib, &b002_abcd_1, empty_nexthop);
  _fib_add_prefix(fib, &b002_3, empty_nexthop);

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

  std::vector<uint32_t> empty_nexthop;
  fib_entry_t *entry = _fib_add_prefix(fib, &b002_128, empty_nexthop);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array_1, used_array_1));

  fib_remove_entry(fib, entry);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array_2, used_array_2));

  entry = _fib_add_prefix(fib, &b002_64, empty_nexthop);
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

  std::vector<uint32_t> empty_nexthop;
  _fib_add_prefix(fib, &b002_128, empty_nexthop);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array_1, used_array_1));

  _fib_add_prefix(fib, &b002_64, empty_nexthop);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));
  EXPECT_TRUE(fib_check_preorder(fib, prefix_array_2, used_array_2));
}

TEST_F(FibTest, IRIStest) {
  char p_0_s[] = "b001:0:0:3039::/64";
  char p_1_3_s[] = "b001::3039:0:1:2:0/128";
  HICN_PREFIX(p_0, p_0_s);

  HICN_PREFIX(p_1_2, "b001::3039:0:1:0:0/128");
  HICN_PREFIX(p_1_1, "b001::3039:0:1:0:100/128");
  HICN_PREFIX(p_1_3, p_1_3_s);
  HICN_PREFIX(p_1_4, "b001::3039:0:1:0:102/128");

  HICN_PREFIX(p_2_2, "b001::3039:0:2:0:0/128");
  HICN_PREFIX(p_2_1, "b001::3039:0:2:0:100/128");
  HICN_PREFIX(p_2_3, "b001::3039:0:2:2:0/128");
  HICN_PREFIX(p_2_4, "b001::3039:0:2:0:102/128");

  HICN_PREFIX(to_match1, "b001::3039:0:1:0:101/128");
  HICN_PREFIX(to_match2, "b001:0:0:3039:ffff:ffff::/128");
  HICN_PREFIX(to_match3, "b001:1::/128");
  HICN_PREFIX(to_match4, "b001::3039:0:1:2:0/128");

  std::vector<uint32_t> nexthop;
  nexthop.push_back(2);  // add nexthop 2 to the fib entry
  /*** add ***/
  _fib_add_prefix(fib, &p_0, nexthop);
  EXPECT_TRUE(fib_is_valid(fib));

  _fib_add_prefix(fib, &p_1_1, nexthop);
  EXPECT_TRUE(fib_is_valid(fib));

  _fib_add_prefix(fib, &p_1_2, nexthop);
  EXPECT_TRUE(fib_is_valid(fib));

  _fib_add_prefix(fib, &p_1_3, nexthop);
  EXPECT_TRUE(fib_is_valid(fib));

  _fib_add_prefix(fib, &p_1_4, nexthop);
  fib_dump(fib);
  EXPECT_TRUE(fib_is_valid(fib));

  /*** match ***/
  fib_entry_t *entry = fib_match_prefix(fib, &to_match1);
  // the matching prefix should be p0
  EXPECT_TRUE(entry != NULL);
  if (entry) {
    int ret = compare_str_prefix_to_prefix(p_0_s, &(entry->prefix));
    EXPECT_EQ(ret, 0);
  }

  entry = fib_match_prefix(fib, &to_match2);
  // the matching prefix should be p0
  EXPECT_TRUE(entry != NULL);
  if (entry) {
    int ret = compare_str_prefix_to_prefix(p_0_s, &(entry->prefix));
    EXPECT_EQ(ret, 0);
  }

  entry = fib_match_prefix(fib, &to_match3);
  // we expect no match
  EXPECT_FALSE(entry != NULL);

  entry = fib_match_prefix(fib, &to_match4);
  // the matching prefix should be p_1_3
  EXPECT_TRUE(entry != NULL);
  if (entry) {
    int ret = compare_str_prefix_to_prefix(p_1_3_s, &(entry->prefix));
    EXPECT_EQ(ret, 0);
  }

  /*** remove ***/
  fib_remove(fib, &p_0, nexthop[0]);
  EXPECT_TRUE(fib_is_valid(fib));
  fib_remove(fib, &p_1_1, nexthop[0]);
  EXPECT_TRUE(fib_is_valid(fib));
  fib_remove(fib, &p_1_2, nexthop[0]);
  EXPECT_TRUE(fib_is_valid(fib));
  fib_remove(fib, &p_1_3, nexthop[0]);
  EXPECT_TRUE(fib_is_valid(fib));
  fib_remove(fib, &p_1_4, nexthop[0]);
  EXPECT_TRUE(fib_is_valid(fib));
  fib_dump(fib);

  /*** match ***/
  entry = fib_match_prefix(fib, &to_match1);
  // we expect no match
  EXPECT_FALSE(entry != NULL);

  entry = fib_match_prefix(fib, &to_match2);
  // we expect no match
  EXPECT_FALSE(entry != NULL);

  entry = fib_match_prefix(fib, &to_match3);
  // we expect no match
  EXPECT_FALSE(entry != NULL);

  entry = fib_match_prefix(fib, &to_match4);
  // we expect no match
  EXPECT_FALSE(entry != NULL);

  // add again
  _fib_add_prefix(fib, &p_0, nexthop);
  EXPECT_TRUE(fib_is_valid(fib));
  _fib_add_prefix(fib, &p_2_1, nexthop);
  EXPECT_TRUE(fib_is_valid(fib));
  _fib_add_prefix(fib, &p_2_2, nexthop);
  EXPECT_TRUE(fib_is_valid(fib));
  _fib_add_prefix(fib, &p_2_3, nexthop);
  EXPECT_TRUE(fib_is_valid(fib));
  _fib_add_prefix(fib, &p_2_4, nexthop);
  EXPECT_TRUE(fib_is_valid(fib));
  fib_dump(fib);

  entry = fib_match_prefix(fib, &to_match1);
  // the matching prefix should be p0
  EXPECT_TRUE(entry != NULL);
  if (entry) {
    int ret = compare_str_prefix_to_prefix(p_0_s, &(entry->prefix));
    EXPECT_EQ(ret, 0);
  }

  entry = fib_match_prefix(fib, &to_match2);
  // the matching prefix should be p0
  EXPECT_TRUE(entry != NULL);
  if (entry) {
    int ret = compare_str_prefix_to_prefix(p_0_s, &(entry->prefix));
    EXPECT_EQ(ret, 0);
  }

  entry = fib_match_prefix(fib, &to_match3);
  // we expect no match
  EXPECT_FALSE(entry != NULL);

  entry = fib_match_prefix(fib, &to_match4);
  // the matching prefix should be p0
  EXPECT_TRUE(entry != NULL);
  if (entry) {
    int ret = compare_str_prefix_to_prefix(p_0_s, &(entry->prefix));
    EXPECT_EQ(ret, 0);
  }
}
