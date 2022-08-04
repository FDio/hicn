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
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>

extern "C"
{
#include <hicn/util/khash.h>
}

KHASH_MAP_INIT_INT (int, unsigned char)

typedef struct
{
  unsigned key;
  unsigned char val;
} int_unpack_t;

typedef struct
{
  unsigned key;
  unsigned char val;
} __attribute__ ((__packed__)) int_packed_t;

#define hash_eq(a, b) ((a).key == (b).key)
#define hash_func(a)  ((a).key)

KHASH_INIT (iun, int_unpack_t, char, 0, hash_func, hash_eq)
KHASH_INIT (ipk, int_packed_t, char, 0, hash_func, hash_eq)

class KHashTest : public ::testing::Test
{
protected:
  KHashTest () {}

  virtual ~KHashTest ()
  {
    // You can do clean-up work that doesn't throw exceptions here.
  }

  // If the constructor and destructor are not enough for setting up
  // and cleaning up each test, you can define the following methods:

  virtual void
  SetUp ()
  {
    khash = kh_init (int);
  }

  virtual void
  TearDown ()
  {
    kh_destroy (int, khash);
  }
  khash_t (int) * khash;
};

TEST_F (KHashTest, KhashIntSize)
{
  int ret;
  int k;
  int size = kh_size (khash);

  EXPECT_EQ (size, 0);
  k = kh_put (int, khash, 10, &ret);
  if (ret == 1)
    {
      kh_val (khash, k) = 10;
    }
  size = kh_size (khash);
  EXPECT_EQ (size, 1);
}

TEST_F (KHashTest, KhashIntPut)
{
  int ret;
  int k;
  k = kh_put (int, khash, 10, &ret);
  if (ret == 1)
    {
      kh_val (khash, k) = 10;
    }
  int size = kh_size (khash);
  EXPECT_EQ (size, 1);
  k = kh_put (int, khash, 20, &ret);
  if (ret == 1)
    {
      kh_val (khash, k) = 20;
    }
  size = kh_size (khash);
  EXPECT_EQ (size, 2);
}

TEST_F (KHashTest, KhashCheckValue)
{
  int ret;
  int k;
  k = kh_put (int, khash, 10, &ret);
  if (ret == 1)
    {
      kh_val (khash, k) = 100;
    }
  k = kh_put (int, khash, 20, &ret);
  if (ret == 1)
    {
      kh_val (khash, k) = 200;
    }

  k = kh_put (int, khash, 10, &ret);
  int val = -1;
  if (!ret)
    val = kh_val (khash, k);
  EXPECT_EQ (val, 100);

  k = kh_put (int, khash, 20, &ret);
  val = -1;
  if (!ret)
    val = kh_val (khash, k);
  EXPECT_EQ (val, 200);
}

// Check that there are no collisions in case of same key hash
typedef struct
{
  int x;
} Key;
#define hash_key(key)	  1 // Hash is always 1 to simulate collisions
#define key_hash_eq(a, b) (a->x == b->x) // Function used in case of collisions
KHASH_INIT (test_map, const Key *, unsigned, 1, hash_key, key_hash_eq);

TEST_F (KHashTest, Collisions)
{
  int ret;
  khiter_t k;

  kh_test_map_t *map = kh_init (test_map);
  Key key1 = { .x = 10 };
  Key key2 = { .x = 11 };

  k = kh_put_test_map (map, &key1, &ret);
  EXPECT_EQ (ret, 1);
  kh_val (map, k) = 15;

  k = kh_put_test_map (map, &key2, &ret);
  EXPECT_EQ (ret, 1);
  kh_val (map, k) = 27;

  k = kh_get_test_map (map, &key1);
  ASSERT_NE (k, kh_end (map));
  unsigned val = kh_val (map, k);
  EXPECT_EQ (val, 15u);

  k = kh_get_test_map (map, &key2);
  ASSERT_NE (k, kh_end (map));
  val = kh_val (map, k);
  EXPECT_EQ (val, 27u);

  kh_destroy_test_map (map);
}
