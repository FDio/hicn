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
#define WITH_TESTS
#include <hicn/util/bitmap.h>
}

#define DEFAULT_SIZE 10

class BitmapTest : public ::testing::Test
{
protected:
  BitmapTest () {}

  virtual ~BitmapTest () {}

  bitmap_t *bitmap;
};

/*
 * TEST: bitmap allocation
 */
TEST_F (BitmapTest, BitmapAllocation)
{
  int rc;

  /*
   * We take a value < 32 on purpose to avoid confusion on the choice of a 32
   * or 64 bit integer for storage
   */
  size_t size_not_pow2 = DEFAULT_SIZE;
  bitmap_init (bitmap, size_not_pow2, 0);

  /*
   * Bitmap should have been allocated with a size rounded to the next power
   * of 2
   */
  EXPECT_EQ (bitmap_get_alloc_size (bitmap), 1UL);

  /* By default, no element should be set */
  EXPECT_FALSE (bitmap_is_set (bitmap, 0));
  EXPECT_TRUE (bitmap_is_unset (bitmap, 0));

  EXPECT_EQ (bitmap_get_alloc_size (bitmap), 1UL);

  EXPECT_FALSE (bitmap_is_set (bitmap, size_not_pow2 - 1));
  EXPECT_TRUE (bitmap_is_unset (bitmap, size_not_pow2 - 1));

  /* Bitmap should not have been reallocated */
  EXPECT_EQ (bitmap_get_alloc_size (bitmap), 1UL);

  /* After setting a bit after the end, bitmap should have been reallocated */
  bitmap_set (bitmap, sizeof (bitmap[0]) * 8 - 1);
  EXPECT_EQ (bitmap_get_alloc_size (bitmap), 1UL);

  /* After setting a bit after the end, bitmap should have been reallocated */
  rc = bitmap_set (bitmap, sizeof (bitmap[0]) * 8);
  EXPECT_GE (rc, 0);
  EXPECT_EQ (bitmap_get_alloc_size (bitmap), 2UL);

  rc = bitmap_set (bitmap, sizeof (bitmap[0]) * 8 + 1);
  EXPECT_GE (rc, 0);
  EXPECT_EQ (bitmap_get_alloc_size (bitmap), 2UL);

  bitmap_free (bitmap);

  size_t size_pow2 = 16;

  /* Limiting test for allocation size */
  bitmap_init (bitmap, size_pow2, 0);
  EXPECT_EQ (bitmap_get_alloc_size (bitmap), 1UL);

  bitmap_free (bitmap);
}

TEST_F (BitmapTest, BitmapSet)
{
  bitmap_init (bitmap, DEFAULT_SIZE, 0);

  bitmap_set (bitmap, 20);
  EXPECT_TRUE (bitmap_is_set (bitmap, 20));
  EXPECT_FALSE (bitmap_is_unset (bitmap, 20));
  EXPECT_FALSE (bitmap_is_set (bitmap, 19));
  EXPECT_TRUE (bitmap_is_unset (bitmap, 19));

  // Test edge cases (i.e. start and end of block)
  off_t start_position = 0;
  bitmap_set (bitmap, start_position);
  EXPECT_TRUE (bitmap_is_set (bitmap, start_position));
  EXPECT_FALSE (bitmap_is_unset (bitmap, start_position));

  off_t end_position = BITMAP_WIDTH (bitmap) - 1;
  bitmap_set (bitmap, end_position);
  EXPECT_TRUE (bitmap_is_set (bitmap, end_position));
  EXPECT_FALSE (bitmap_is_unset (bitmap, end_position));

  bitmap_free (bitmap);
}

TEST_F (BitmapTest, BitmapUnSet)
{
  bitmap_init (bitmap, DEFAULT_SIZE, 0);

  bitmap_set (bitmap, 20);
  bitmap_set (bitmap, 19);
  bitmap_unset (bitmap, 20);
  EXPECT_FALSE (bitmap_is_set (bitmap, 20));
  EXPECT_TRUE (bitmap_is_unset (bitmap, 20));
  EXPECT_TRUE (bitmap_is_set (bitmap, 19));
  EXPECT_FALSE (bitmap_is_unset (bitmap, 19));

  bitmap_free (bitmap);
}

TEST_F (BitmapTest, BitmapSetTo)
{
  bitmap_init (bitmap, DEFAULT_SIZE, 0);

  bitmap_set_to (bitmap, 40);
  EXPECT_TRUE (bitmap_is_set (bitmap, 20));
  EXPECT_TRUE (bitmap_is_set (bitmap, 21));
  EXPECT_TRUE (bitmap_is_unset (bitmap, 41));
  EXPECT_TRUE (bitmap_is_unset (bitmap, 42));

  bitmap_free (bitmap);
}

TEST_F (BitmapTest, BitmapFirstSet)
{
  bitmap_init (bitmap, DEFAULT_SIZE, 0);

  // Get first set bit. It should be INVALID_INDEX
  EXPECT_EQ (bitmap_first_set (bitmap), BITMAP_INVALID_INDEX);

  // set bit 40
  bitmap_set (bitmap, 40);
  EXPECT_TRUE (bitmap_is_set (bitmap, 40));

  // Get first set bit. It should be bit 40 (surprise):)
  EXPECT_EQ (bitmap_first_set (bitmap), hicn_uword (40));

  // set bit 3
  bitmap_set (bitmap, 3);
  EXPECT_TRUE (bitmap_is_set (bitmap, 3));

  // The first set bit now should be bit #3
  EXPECT_EQ (bitmap_first_set (bitmap), hicn_uword (3));

  bitmap_free (bitmap);
}

TEST_F (BitmapTest, BitmapFirstUnSet)
{
  bitmap_init (bitmap, DEFAULT_SIZE, 0);

  // Get first unset bit. It should be 0
  EXPECT_EQ (bitmap_first_unset (bitmap), hicn_uword (0));

  // set bit 0
  bitmap_set (bitmap, 0);
  EXPECT_TRUE (bitmap_is_set (bitmap, 0));

  // Get first unset bit. It should be bit 1
  EXPECT_EQ (bitmap_first_unset (bitmap), hicn_uword (1));

  // set bit 3
  bitmap_set (bitmap, 3);
  EXPECT_TRUE (bitmap_is_set (bitmap, 3));

  // The first set bit now should be still 1
  EXPECT_EQ (bitmap_first_unset (bitmap), hicn_uword (1));

  bitmap_free (bitmap);
}

TEST_F (BitmapTest, BitmapNextSet)
{
  bitmap_init (bitmap, DEFAULT_SIZE, 0);

  // Get next unset bit >= 0. It should be INVALID
  EXPECT_EQ (bitmap_next_set (bitmap, 0), BITMAP_INVALID_INDEX);

  // set bit 0
  bitmap_set (bitmap, 0);
  EXPECT_TRUE (bitmap_is_set (bitmap, 0));

  // Get next set bit >= 0. It should be bit 0
  EXPECT_EQ (bitmap_next_set (bitmap, 0), hicn_uword (0));

  // set bit 3
  bitmap_set (bitmap, 3);
  EXPECT_TRUE (bitmap_is_set (bitmap, 3));

  // Get next set bit >= 1. It should be 3
  EXPECT_EQ (bitmap_next_set (bitmap, 1), hicn_uword (3));

  // set (N-2)th bit
  bitmap_set (bitmap, DEFAULT_SIZE * WORD_WIDTH - 2);
  EXPECT_TRUE (bitmap_is_set (bitmap, DEFAULT_SIZE * WORD_WIDTH - 2));
  EXPECT_EQ (bitmap_next_set (bitmap, DEFAULT_SIZE * WORD_WIDTH - 3),
	     DEFAULT_SIZE * WORD_WIDTH - 2);

  // set (N-1)th bit
  bitmap_unset (bitmap, DEFAULT_SIZE * WORD_WIDTH - 2);
  bitmap_set (bitmap, DEFAULT_SIZE * WORD_WIDTH - 1);
  EXPECT_TRUE (bitmap_is_set (bitmap, DEFAULT_SIZE * WORD_WIDTH - 1));
  EXPECT_EQ (bitmap_next_set (bitmap, DEFAULT_SIZE * WORD_WIDTH - 2),
	     DEFAULT_SIZE * WORD_WIDTH - 1);
  EXPECT_EQ (bitmap_next_set (bitmap, DEFAULT_SIZE * WORD_WIDTH - 1),
	     DEFAULT_SIZE * WORD_WIDTH - 1);

  bitmap_free (bitmap);
}

TEST_F (BitmapTest, BitmapNextUnSet)
{
  bitmap_init (bitmap, DEFAULT_SIZE, 0);

  // Get next unset bit >= 0. It should be 0
  EXPECT_EQ (bitmap_next_unset (bitmap, 0), hicn_uword (0));

  // set bit 0
  bitmap_set (bitmap, 0);
  EXPECT_TRUE (bitmap_is_set (bitmap, 0));

  // Get next set bit >= 0. It should be bit 1
  EXPECT_EQ (bitmap_next_unset (bitmap, 0), hicn_uword (1));

  // set bit 3
  bitmap_set (bitmap, 3);
  EXPECT_TRUE (bitmap_is_set (bitmap, 3));

  // Get next unset bit after 3. It should be 4
  EXPECT_EQ (bitmap_next_unset (bitmap, 3), hicn_uword (4));

  bitmap_free (bitmap);
}
