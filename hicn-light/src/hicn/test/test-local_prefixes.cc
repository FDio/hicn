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

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>

extern "C" {
#define WITH_TESTS
#include <hicn/strategies/local_prefixes.h>
#include <hicn/core/strategy.h>
}

const char *name_str1 = "b001::0";
const char *name_str2 = "b002::0";
const char *name_str3 = "b003::0";
const char *name_str4 = "b004::0";
const char *name_str5 = "b005::0";
const char *name_str6 = "b006::0";
const char *name_str7 = "b007::0";
const char *name_str8 = "b008::0";
const char *name_str9 = "b009::0";
const char *name_str10 = "b010::0";
const char *name_str11 = "b011::0";

class LocalPrefixesTest : public ::testing::Test {
 protected:
  LocalPrefixesTest() {}

  virtual ~LocalPrefixesTest() {}
};

TEST_F(LocalPrefixesTest, LocalPrefixesAddName) {
  int rc;
  local_prefixes_t *lp = create_local_prefixes();
  EXPECT_FALSE(lp == nullptr);

  hicn_ip_address_t result = IP_ADDRESS_EMPTY;
  hicn_ip_address_pton(name_str1, &result);
  hicn_prefix_t name1;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name1);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str2, &result);
  hicn_prefix_t name2;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name2);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str3, &result);
  hicn_prefix_t name3;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name3);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str4, &result);
  hicn_prefix_t name4;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name4);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str5, &result);
  hicn_prefix_t name5;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name5);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str6, &result);
  hicn_prefix_t name6;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name6);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str7, &result);
  hicn_prefix_t name7;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name7);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str8, &result);
  hicn_prefix_t name8;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name8);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str9, &result);
  hicn_prefix_t name9;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name9);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str10, &result);
  hicn_prefix_t name10;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name10);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str11, &result);
  hicn_prefix_t name11;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name11);
  EXPECT_EQ(rc, 0);

  local_prefixes_add_prefix(lp, &name1);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)1);

  local_prefixes_add_prefix(lp, &name1);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)1);

  local_prefixes_add_prefix(lp, &name2);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)2);

  local_prefixes_add_prefix(lp, &name2);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)2);

  local_prefixes_add_prefix(lp, &name3);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)3);

  local_prefixes_add_prefix(lp, &name4);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)4);

  local_prefixes_add_prefix(lp, &name5);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)5);

  local_prefixes_add_prefix(lp, &name6);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)6);

  local_prefixes_add_prefix(lp, &name7);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)7);

  local_prefixes_add_prefix(lp, &name8);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)8);

  local_prefixes_add_prefix(lp, &name9);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)9);

  local_prefixes_add_prefix(lp, &name10);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)10);

  local_prefixes_add_prefix(lp, &name11);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)10);

  free_local_prefixes(lp);
}

TEST_F(LocalPrefixesTest, LocalPrefixesAddPrefixes) {
  int rc;
  local_prefixes_t *lp = create_local_prefixes();
  EXPECT_FALSE(lp == nullptr);

  hicn_ip_address_t result;

  local_prefixes_t *lp1 = create_local_prefixes();
  EXPECT_FALSE(lp1 == nullptr);

  hicn_ip_address_pton(name_str1, &result);
  hicn_prefix_t name1;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name1);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str2, &result);
  hicn_prefix_t name2;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name2);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str3, &result);
  hicn_prefix_t name3;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name3);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str4, &result);
  hicn_prefix_t name4;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name4);
  EXPECT_EQ(rc, 0);

  local_prefixes_add_prefix(lp1, &name1);
  local_prefixes_add_prefix(lp1, &name2);
  local_prefixes_add_prefix(lp1, &name3);
  local_prefixes_add_prefix(lp1, &name4);

  EXPECT_EQ(local_prefixes_get_len(lp1), (unsigned)4);

  local_prefixes_add_prefixes(lp, lp1);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)4);

  local_prefixes_add_prefixes(lp, lp1);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)4);

  local_prefixes_t *lp2 = create_local_prefixes();
  EXPECT_FALSE(lp2 == nullptr);

  hicn_ip_address_pton(name_str5, &result);
  hicn_prefix_t name5;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name5);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str6, &result);
  hicn_prefix_t name6;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name6);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str7, &result);
  hicn_prefix_t name7;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name7);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str8, &result);
  hicn_prefix_t name8;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name8);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str9, &result);
  hicn_prefix_t name9;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name9);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str10, &result);
  hicn_prefix_t name10;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name10);
  EXPECT_EQ(rc, 0);

  hicn_ip_address_pton(name_str11, &result);
  hicn_prefix_t name11;
  rc = hicn_prefix_create_from_ip_address_len(&result, 128, &name11);
  EXPECT_EQ(rc, 0);

  local_prefixes_add_prefix(lp2, &name5);
  local_prefixes_add_prefix(lp2, &name6);
  local_prefixes_add_prefix(lp2, &name7);
  local_prefixes_add_prefix(lp2, &name8);
  local_prefixes_add_prefix(lp2, &name9);
  local_prefixes_add_prefix(lp2, &name10);
  local_prefixes_add_prefix(lp2, &name11);

  EXPECT_EQ(local_prefixes_get_len(lp2), (unsigned)7);

  local_prefixes_add_prefixes(lp, lp2);
  EXPECT_EQ(local_prefixes_get_len(lp), (unsigned)10);

  free_local_prefixes(lp);
  free_local_prefixes(lp1);
  free_local_prefixes(lp2);
}
