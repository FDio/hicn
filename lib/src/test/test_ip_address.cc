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

#include <stdio.h>
#include <stdlib.h>

extern "C"
{
#define WITH_TESTS
#include <hicn/util/ip_address.h>
}

#define DEFAULT_SIZE 10

class IPAddressTest : public ::testing::Test
{
protected:
  IPAddressTest () {}

  virtual ~IPAddressTest () {}
};

TEST_F (IPAddressTest, IPAddressGetBit)
{
  hicn_ip_address_t a_0, a_1, a_1_0, a_1_1, a_1_48, a_1_49, a_1_63, a_1_64, a_1_127;

  hicn_ip_address_pton ("0::0", &a_0);
  hicn_ip_address_pton ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &a_1);

  hicn_ip_address_pton ("8000::0", &a_1_0);
  hicn_ip_address_pton ("4000::0", &a_1_1);
  hicn_ip_address_pton ("0:0:0:8000::0", &a_1_48);
  hicn_ip_address_pton ("0:0:0:4000::0", &a_1_49);
  hicn_ip_address_pton ("0:0:0:1::0", &a_1_63);
  hicn_ip_address_pton ("0::8000:0:0:0", &a_1_64);
  hicn_ip_address_pton ("0::1", &a_1_127);

#if 0
  for (unsigned i = 0; i < 128; i++)
    EXPECT_EQ (hicn_ip_address_get_bit (&a_0, i), 0);
  for (unsigned i = 0; i < 128; i++)
    EXPECT_EQ (hicn_ip_address_get_bit (&a_1, i), 1);
#endif
  for (unsigned i = 0; i < 128; i++)
    EXPECT_EQ (hicn_ip_address_get_bit (&a_1_0, i), (i == 0) ? 1 : 0);
  for (unsigned i = 0; i < 128; i++)
    EXPECT_EQ (hicn_ip_address_get_bit (&a_1_1, i), (i == 1) ? 1 : 0);
  for (unsigned i = 0; i < 128; i++)
    EXPECT_EQ (hicn_ip_address_get_bit (&a_1_48, i), (i == 48) ? 1 : 0);
  for (unsigned i = 0; i < 128; i++)
    EXPECT_EQ (hicn_ip_address_get_bit (&a_1_49, i), (i == 49) ? 1 : 0);
  for (unsigned i = 0; i < 128; i++)
    EXPECT_EQ (hicn_ip_address_get_bit (&a_1_63, i), (i == 63) ? 1 : 0);
  for (unsigned i = 0; i < 128; i++)
    EXPECT_EQ (hicn_ip_address_get_bit (&a_1_64, i), (i == 64) ? 1 : 0);
  for (unsigned i = 0; i < 128; i++)
    EXPECT_EQ (hicn_ip_address_get_bit (&a_1_127, i), (i == 127) ? 1 : 0);
}
