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
#include <gmock/gmock.h>

extern "C"
{
#include <hicn/interest_manifest.h>
}

static constexpr hicn_uword WORD_SIZE = WORD_WIDTH;

class InterestManifestTest : public ::testing::Test
{
protected:
  static constexpr u32 n_suffixes = 0x00000014;
  static constexpr u32 padding = 0x21232425;
  static constexpr hicn_uword bitmap_word = ~0ULL;
  static inline std::vector<uint32_t> values = { 10, 22, 23, 43, 54, 65, 66,
						 4,  33, 2,  44, 99, 87, 67,
						 78, 98, 76, 1,	 7,  123 };
  InterestManifestTest () {}
  virtual ~InterestManifestTest () {}

  uint8_t buffer[512];
  hicn_uword bitmap_saved[BITMAP_SIZE];
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

TEST_F (InterestManifestTest, SerializeDeserialize)
{
#if hicn_uword_bits == 64
#define F(x) hicn_host_to_net_64 (x)
#elif hicn_uword_bits == 32
#define F(x) hicn_host_to_net_32 (x)
#else
#error "Unrecognized architecture"
#endif

  auto header = reinterpret_cast<interest_manifest_header_t *> (buffer);
  interest_manifest_init (header);

  for (const auto &v : values)
    {
      interest_manifest_add_suffix (header, v);
    }

  EXPECT_EQ (header->n_suffixes, n_suffixes);

  // Save bitmap
  memcpy (bitmap_saved, header->request_bitmap, sizeof (bitmap_saved));

  // Serialize manifest
  interest_manifest_serialize (header);

  // If architecture is little endian, bytes should be now swapped
  EXPECT_THAT (header->n_suffixes, ::testing::Eq (hicn_host_to_net_32 (
				     n_suffixes) /* 0x14000000 */));

  for (unsigned i = 0; i < BITMAP_SIZE; i++)
    {
      EXPECT_THAT (header->request_bitmap[i],
		   ::testing::Eq (F (bitmap_saved[i])));
    }

  hicn_name_suffix_t *suffix = (hicn_name_suffix_t *) (header + 1);
  for (unsigned i = 0; i < n_suffixes; i++)
    {
      EXPECT_THAT (*(suffix + i),
		   ::testing::Eq (hicn_host_to_net_32 (values[i])));
    }

  // Deserialize manifest
  interest_manifest_deserialize (header);

  // Bytes should now be as before
  EXPECT_THAT (header->n_suffixes, ::testing::Eq (n_suffixes));

  int i = 0;
  interest_manifest_foreach_suffix (header, suffix)
  {
    EXPECT_THAT (*suffix, ::testing::Eq (values[i]));
    i++;
  }
}

TEST_F (InterestManifestTest, ForEach)
{
  auto header = reinterpret_cast<interest_manifest_header_t *> (buffer);
  header->n_suffixes = n_suffixes;
  header->padding = padding;
  memset (header->request_bitmap, 0xff, BITMAP_SIZE * sizeof (hicn_uword));

  hicn_name_suffix_t *suffix = (hicn_name_suffix_t *) (header + 1);
  for (uint32_t i = 0; i < n_suffixes; i++)
    {
      *(suffix + i) = values[i];
    }

  // Iterate over interest manifest. As bitmap is all 1, we should be able to
  // iterate over all suffixes.
  unsigned i = 0;
  interest_manifest_foreach_suffix (header, suffix)
  {
    EXPECT_EQ (*suffix, values[i]);
    i++;
  }

  std::set<uint32_t> set_values (values.begin (), values.end ());

  // Unset few bitmap positions
  interest_manifest_del_suffix (header, 5);
  set_values.erase (values[5]);

  interest_manifest_del_suffix (header, 6);
  set_values.erase (values[6]);

  interest_manifest_del_suffix (header, 12);
  set_values.erase (values[12]);

  interest_manifest_del_suffix (header, 17);
  set_values.erase (values[17]);

  // Iterate over interest manifest and remove elements in manifest from set.
  // The set should be empty at the end.
  interest_manifest_foreach_suffix (header, suffix)
  {
    std::cout << suffix - _FIRST (header) << std::endl;
    EXPECT_TRUE (set_values.find (*suffix) != set_values.end ())
      << "The value was " << *suffix;
    set_values.erase (*suffix);
  }

  EXPECT_TRUE (set_values.empty ());
}