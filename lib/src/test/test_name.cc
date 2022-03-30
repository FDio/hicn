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

extern "C"
{
#include <hicn/name.h>
#include <hicn/common.h>
#include <hicn/error.h>
}

class NameTest : public ::testing::Test
{
protected:
  const char *ipv6_prefix = "b001::abcd:1234:abcd:1234";
  const char *ipv4_prefix = "12.13.14.15";
  const uint32_t suffix = 12345;

  NameTest () : name_{}, name4_{}, name6_{}
  {
    int rc = inet_pton (AF_INET6, ipv6_prefix, &ipv6_prefix_bytes.v6);
    EXPECT_EQ (rc, 1);

    rc = inet_pton (AF_INET, ipv4_prefix, &ipv4_prefix_bytes.v4);
    EXPECT_EQ (rc, 1);

    rc = hicn_name_create (ipv4_prefix, suffix, &name4_);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
    rc = hicn_name_create (ipv6_prefix, suffix, &name6_);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  }

  virtual ~NameTest () {}

  void
  nameHashTest (const char *prefix)
  {
    // Create 2 names
    uint32_t suffix = 13579;
    hicn_name_t name_a, name_b;
    int rc = hicn_name_create (prefix, suffix, &name_a);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
    rc = hicn_name_create (prefix, suffix, &name_b);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

    // The hash should be equal, with and without considering the suffix
    uint32_t hash_a, hash_b;
    rc = hicn_name_hash (&name_a, &hash_a, 1);
    EXPECT_EQ (rc, 0);
    rc = hicn_name_hash (&name_b, &hash_b, 1);
    EXPECT_EQ (rc, 0);
    EXPECT_EQ (hash_a, hash_b);

    rc = hicn_name_hash (&name_a, &hash_a, 0);
    EXPECT_EQ (rc, 0);
    rc = hicn_name_hash (&name_b, &hash_b, 0);
    EXPECT_EQ (rc, 0);
    EXPECT_EQ (hash_a, hash_b);

    // Now let's change the suffix
    rc = hicn_name_set_seq_number (&name_a, 97531);
    // They should result equal if we do not consider the suffix
    rc = hicn_name_hash (&name_a, &hash_a, 0);
    EXPECT_EQ (rc, 0);
    rc = hicn_name_hash (&name_b, &hash_b, 0);
    EXPECT_EQ (rc, 0);
    EXPECT_EQ (hash_a, hash_b);

    // And different if we consider it
    rc = hicn_name_hash (&name_a, &hash_a, 1);
    EXPECT_EQ (rc, 0);
    rc = hicn_name_hash (&name_b, &hash_b, 1);
    EXPECT_EQ (rc, 0);
    EXPECT_NE (hash_a, hash_b);
  }

  void
  nameCopyTest (const char *prefix)
  {
    uint32_t suffix = 13579;
    hicn_name_t name_a, name_b;
    int rc = hicn_name_create (prefix, suffix, &name_a);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

    rc = hicn_name_copy (&name_b, &name_a);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

    rc = hicn_name_compare (&name_a, &name_b, 1);
    EXPECT_EQ (rc, 0);
  }

  void
  nameCompareTest (const char *prefix)
  {
    // Create 2 names
    uint32_t suffix = 13579;
    hicn_name_t name_a, name_b;
    int rc = hicn_name_create (prefix, suffix, &name_a);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
    rc = hicn_name_create (prefix, suffix, &name_b);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

    // They should be equal, with and without considering the suffix
    rc = hicn_name_compare (&name_a, &name_b, 1);
    EXPECT_EQ (rc, 0);
    rc = hicn_name_compare (&name_a, &name_b, 0);
    EXPECT_EQ (rc, 0);

    // Now let's change the suffix
    rc = hicn_name_set_seq_number (&name_a, 97531);
    // They should result equal if we do not consider the suffix
    rc = hicn_name_compare (&name_a, &name_b, 0);
    EXPECT_EQ (rc, 0);
    // And different if we consider the suffix
    rc = hicn_name_compare (&name_a, &name_b, 1);
    EXPECT_NE (rc, 0);
  }

  void
  nameFromIpPrefixTest (const ip_prefix_t &ip_prefix)
  {
    uint32_t suffix = 54321;
    hicn_name_t name;
    int rc = hicn_name_create_from_ip_prefix (&ip_prefix, suffix, &name);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
    rc = memcmp (ip_prefix.address.v6.as_u8, name.prefix.v6.as_u8,
		 sizeof (name.prefix.v6));
    EXPECT_EQ (rc, 0);
    EXPECT_EQ (suffix, name.suffix);
  }

  void
  nameToIpPrefixTest (const char *prefix)
  {
    uint32_t suffix = 54321;
    hicn_name_t name;
    int rc = hicn_name_create (prefix, suffix, &name);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

    // Get family
    int family;
    rc = hicn_name_get_family (&name, &family);

    ip_prefix_t ip_prefix;
    rc = hicn_name_to_ip_prefix (&name, &ip_prefix);
    EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
    EXPECT_EQ (ip_prefix.family, family);
    rc = ip_address_cmp (&ip_prefix.address, &name.prefix, AF_INET6);
    EXPECT_EQ (rc, 0);
  }

  hicn_name_t name_, name4_, name6_;
  ip_address_t ipv6_prefix_bytes, ipv4_prefix_bytes;
};

/**
 * Name Initialization
 */
TEST_F (NameTest, NameInitialization)
{
  EXPECT_TRUE (_is_unspec (&name_));
  uint32_t suffix = 12345;

  // Initialize ipv6 name
  hicn_name_t name6;
  int rc = hicn_name_create (ipv6_prefix, suffix, &name6);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  // Check name is correctly created
  rc = ip_address_cmp (&name6.prefix, &ipv6_prefix_bytes, AF_INET6);
  EXPECT_EQ (rc, 0);
  EXPECT_EQ (name6.suffix, suffix);

  // Initialize ipv4 name
  hicn_name_t name4;
  rc = hicn_name_create (ipv4_prefix, suffix, &name4);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  // Check name is correctly created
  rc = ip_address_cmp (&name4.prefix, &ipv4_prefix_bytes, AF_INET);
  EXPECT_EQ (name4.prefix.pad[0], 0UL);
  EXPECT_EQ (name4.prefix.pad[1], 0UL);
  EXPECT_EQ (name4.prefix.pad[2], 0UL);
  EXPECT_EQ (rc, 0);
  EXPECT_EQ (name4.suffix, suffix);

  // Try also to reuse previously initialized name
  rc = hicn_name_create (ipv4_prefix, suffix, &name6);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  // Check name is correctly created
  rc = ip_address_cmp (&name6.prefix, &ipv4_prefix_bytes, AF_INET);
  EXPECT_EQ (name6.prefix.pad[0], 0UL);
  EXPECT_EQ (name6.prefix.pad[1], 0UL);
  EXPECT_EQ (name6.prefix.pad[2], 0UL);
  EXPECT_EQ (rc, 0);
  EXPECT_EQ (name6.suffix, suffix);
}

/**
 * Name from ip prefix
 */
TEST_F (NameTest, NameFromIpPrefix6)
{
  ip_prefix_t ip_prefix = { .family = AF_INET6, .address = {}, .len = 64 };

  ip_prefix.address.v6.as_u64[0] = ipv6_prefix_bytes.v6.as_u64[0];
  ip_prefix.address.v6.as_u64[1] = ipv6_prefix_bytes.v6.as_u64[1];

  nameFromIpPrefixTest (ip_prefix);
}

TEST_F (NameTest, NameFromIpPrefix4)
{
  ip_prefix_t ip_prefix = { .family = AF_INET, .address = {}, .len = 64 };
  ip_prefix.address.v4.as_u32 = ipv4_prefix_bytes.v4.as_u32;
  ip_prefix.address.pad[0] = 0;
  ip_prefix.address.pad[1] = 0;
  ip_prefix.address.pad[2] = 0;
  nameFromIpPrefixTest (ip_prefix);
}

TEST_F (NameTest, NameCompare6) { nameCompareTest (ipv6_prefix); }

TEST_F (NameTest, NameCompare4) { nameCompareTest (ipv4_prefix); }

TEST_F (NameTest, NameHash6) { nameHashTest (ipv6_prefix); }

TEST_F (NameTest, NameHash4) { nameHashTest (ipv4_prefix); }

TEST_F (NameTest, NameEmpty)
{
  int rc = hicn_name_empty (&name_);
  EXPECT_EQ (rc, 1);

  name_.prefix.v6 = ipv6_prefix_bytes.v6;
  rc = hicn_name_empty (&name_);
  EXPECT_EQ (rc, 0);
}

TEST_F (NameTest, NameCopy6) { nameCopyTest (ipv6_prefix); }

TEST_F (NameTest, NameCopy4) { nameCopyTest (ipv4_prefix); }

TEST_F (NameTest, NameCopyToDestination)
{
  ip4_address_t dst4;
  ip6_address_t dst6;

  // Copy names to destination
  int rc = hicn_name_copy_prefix_to_destination (dst4.as_u8, &name4_);
  EXPECT_EQ (rc, 0);
  rc = hicn_name_copy_prefix_to_destination (dst6.as_u8, &name6_);
  EXPECT_EQ (rc, 0);

  // Check copy succeeded
  EXPECT_TRUE (dst4.as_u32 == name4_.prefix.v4.as_u32);
  EXPECT_TRUE (dst6.as_u64[0] == name6_.prefix.v6.as_u64[0]);
  EXPECT_TRUE (dst6.as_u64[1] == name6_.prefix.v6.as_u64[1]);
}

TEST_F (NameTest, SetGetSuffix)
{
  uint32_t suffix2 = 55555, suffix_ret;

  // Check if suffix is correct
  int rc = hicn_name_get_seq_number (&name6_, &suffix_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (suffix, suffix_ret);

  // Set new suffix
  rc = hicn_name_set_seq_number (&name6_, suffix2);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  // Check suffix was set
  rc = hicn_name_get_seq_number (&name6_, &suffix_ret);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (suffix2, suffix_ret);
}

TEST_F (NameTest, NameToSockAddr)
{
  struct sockaddr_in saddr4;
  struct sockaddr_in6 saddr6;

  int rc =
    hicn_name_to_sockaddr_address (&name6_, (struct sockaddr *) (&saddr6));
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  rc = memcmp (name6_.prefix.v6.as_u8, saddr6.sin6_addr.s6_addr,
	       sizeof (name6_.prefix.v6));
  EXPECT_EQ (rc, 0);

  rc = hicn_name_to_sockaddr_address (&name4_, (struct sockaddr *) (&saddr4));
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);
  EXPECT_EQ (name4_.prefix.v4.as_u32, saddr4.sin_addr.s_addr);
}

TEST_F (NameTest, NameToIpPrefix)
{
  nameToIpPrefixTest (ipv4_prefix);
  nameToIpPrefixTest (ipv6_prefix);
}

TEST_F (NameTest, NameNToP)
{
  char dst[128];

  // V6
  int rc = hicn_name_ntop (&name6_, dst, 128);
  EXPECT_EQ (rc, HICN_LIB_ERROR_NONE);

  // Build expected name
  std::stringstream expected6;
  expected6 << ipv6_prefix << "|" << suffix;

  rc = strcmp (dst, expected6.str ().c_str ());
  EXPECT_EQ (rc, 0);

  // V4
  rc = hicn_name_ntop (&name4_, dst, 128);
  std::stringstream expected4;
  expected4 << ipv4_prefix << "|" << suffix;

  rc = strcmp (dst, expected4.str ().c_str ());
  EXPECT_EQ (rc, 0);
}
