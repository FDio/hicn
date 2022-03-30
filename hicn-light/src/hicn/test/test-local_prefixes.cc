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
#include <arpa/inet.h>

extern "C" {
#define WITH_TESTS
#include <hicn/strategies/local_prefixes.h>
#include <hicn/core/strategy.h>
#include <hicn/core/name.h>
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
  local_prefixes_t *lp = create_local_prefixes();
  EXPECT_FALSE(lp == nullptr);

  ip_address_t result;
  inet_pton(AF_INET6, name_str1, (struct in6_addr *)&result);
  Name name1;
  name_CreateFromAddress(&name1, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str2, (struct in6_addr *)&result);
  Name name2;
  name_CreateFromAddress(&name2, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str3, (struct in6_addr *)&result);
  Name name3;
  name_CreateFromAddress(&name3, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str4, (struct in6_addr *)&result);
  Name name4;
  name_CreateFromAddress(&name4, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str5, (struct in6_addr *)&result);
  Name name5;
  name_CreateFromAddress(&name5, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str6, (struct in6_addr *)&result);
  Name name6;
  name_CreateFromAddress(&name6, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str7, (struct in6_addr *)&result);
  Name name7;
  name_CreateFromAddress(&name7, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str8, (struct in6_addr *)&result);
  Name name8;
  name_CreateFromAddress(&name8, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str9, (struct in6_addr *)&result);
  Name name9;
  name_CreateFromAddress(&name9, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str10, (struct in6_addr *)&result);
  Name name10;
  name_CreateFromAddress(&name10, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str11, (struct in6_addr *)&result);
  Name name11;
  name_CreateFromAddress(&name11, AF_INET6, result, 128);

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
  local_prefixes_t *lp = create_local_prefixes();
  EXPECT_FALSE(lp == nullptr);

  ip_address_t result;

  local_prefixes_t *lp1 = create_local_prefixes();
  EXPECT_FALSE(lp1 == nullptr);

  inet_pton(AF_INET6, name_str1, (struct in6_addr *)&result);
  Name name1;
  name_CreateFromAddress(&name1, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str2, (struct in6_addr *)&result);
  Name name2;
  name_CreateFromAddress(&name2, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str3, (struct in6_addr *)&result);
  Name name3;
  name_CreateFromAddress(&name3, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str4, (struct in6_addr *)&result);
  Name name4;
  name_CreateFromAddress(&name4, AF_INET6, result, 128);

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

  inet_pton(AF_INET6, name_str5, (struct in6_addr *)&result);
  Name name5;
  name_CreateFromAddress(&name5, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str6, (struct in6_addr *)&result);
  Name name6;
  name_CreateFromAddress(&name6, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str7, (struct in6_addr *)&result);
  Name name7;
  name_CreateFromAddress(&name7, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str8, (struct in6_addr *)&result);
  Name name8;
  name_CreateFromAddress(&name8, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str9, (struct in6_addr *)&result);
  Name name9;
  name_CreateFromAddress(&name9, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str10, (struct in6_addr *)&result);
  Name name10;
  name_CreateFromAddress(&name10, AF_INET6, result, 128);

  inet_pton(AF_INET6, name_str11, (struct in6_addr *)&result);
  Name name11;
  name_CreateFromAddress(&name11, AF_INET6, result, 128);

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
