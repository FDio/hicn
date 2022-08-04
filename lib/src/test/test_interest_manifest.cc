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
#include <hicn/interest_manifest.h>
}

static constexpr hicn_uword WORD_SIZE = WORD_WIDTH;

class InterestManifestTest : public ::testing::Test
{
protected:
  InterestManifestTest () {}
  virtual ~InterestManifestTest () {}
};

TEST_F (InterestManifestTest, OneWordBitmapUpdate)
{
  hicn_uword initial_bitmap[1];
  hicn_uword curr_bitmap[1] = { 0 };
  initial_bitmap[0] =
    0x0000000000000b07; // ...000000000000000000000101100000111

  // Consume first 4 'one' bits (i.e. suffixes), reaching position 9
  size_t pos = 0, max_suffixes = 4;
  pos = interest_manifest_update_bitmap (initial_bitmap, curr_bitmap, pos,
					 WORD_SIZE, max_suffixes);
  EXPECT_EQ (pos, std::size_t (9));
  EXPECT_EQ (curr_bitmap[0], hicn_uword (0x0000000000000107));

  // Consume the remaining 2 'one' bits, reaching end of bitmap
  hicn_uword curr_bitmap2[1] = { 0 };
  pos = interest_manifest_update_bitmap (initial_bitmap, curr_bitmap2, pos,
					 WORD_SIZE, max_suffixes);
  EXPECT_EQ (pos, WORD_SIZE);
  EXPECT_EQ (curr_bitmap2[0], hicn_uword (0x00000a00));

  // Consume all suffixes at once
  hicn_uword curr_bitmap3[1] = { 0 };
  max_suffixes = 16;
  pos = interest_manifest_update_bitmap (initial_bitmap, curr_bitmap3, 0,
					 WORD_SIZE, max_suffixes);
  EXPECT_EQ (pos, WORD_SIZE);
  EXPECT_EQ (curr_bitmap3[0], initial_bitmap[0]);
}

TEST_F (InterestManifestTest, TwoWordBitmapUpdate)
{
  hicn_uword initial_bitmap[2];
  initial_bitmap[0] = 0x0000000000000b07;
  initial_bitmap[1] = 0x0000000000000b07;
  // -> 0000000000000000000010110000011100000000000000000000101100000111

  int expected_pos[] = { WORD_SIZE + 2, 2 * WORD_SIZE };
  u32 expected_bitmap[][2] = { { 0x00000b07, 0x00000003 },
			       { 0x0, 0x00000b04 } };

  // Loop to consume all suffixes
  int pos = 0, max_suffixes = 8, i = 0, len = WORD_SIZE * 2;
  while (pos != len)
    {
      hicn_uword curr_bitmap[2] = { 0 };
      pos = interest_manifest_update_bitmap (initial_bitmap, curr_bitmap, pos,
					     len, max_suffixes);

      EXPECT_EQ (pos, expected_pos[i]);
      EXPECT_EQ (curr_bitmap[0], expected_bitmap[i][0]);
      EXPECT_EQ (curr_bitmap[1], expected_bitmap[i][1]);
      i++;
    }
}