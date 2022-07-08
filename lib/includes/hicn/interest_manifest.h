/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#ifndef HICNLIGHT_INTEREST_MANIFEST_H
#define HICNLIGHT_INTEREST_MANIFEST_H

#include <string.h>
#include <stdbool.h>

#include <hicn/util/bitmap.h>
#include <hicn/base.h>
#include <hicn/name.h>
#include <hicn/common.h>

typedef enum
{
  INT_MANIFEST_SPLIT_STRATEGY_NONE,
  INT_MANIFEST_SPLIT_STRATEGY_MAX_N_SUFFIXES,
  INT_MANIFEST_SPLIT_N_STRATEGIES,
} int_manifest_split_strategy_t;

#define MAX_SUFFIXES_IN_MANIFEST 256

#define DEFAULT_DISAGGREGATION_STRATEGY                                       \
  INT_MANIFEST_SPLIT_STRATEGY_MAX_N_SUFFIXES
#define DEFAULT_N_SUFFIXES_PER_SPLIT MAX_SUFFIXES_IN_MANIFEST

#define BITMAP_SIZE (MAX_SUFFIXES_IN_MANIFEST / WORD_WIDTH)

typedef struct
{
  /* This can be 16 bits, but we use 32 bits for alignment */
  uint32_t n_suffixes;

  /* Align to 64 bits */
  uint32_t padding;

  hicn_uword request_bitmap[BITMAP_SIZE];

  /* Followed by the list of prefixes to ask */
  /* ... */
} interest_manifest_header_t;

static_assert (sizeof (interest_manifest_header_t) == 32 + 4 + 4,
	       "interest_manifest_header_t size must be exactly 40 bytes");

#define _interest_manifest_serialize_deserialize(manifest, first, second,     \
						 size, serialize)             \
  do                                                                          \
    {                                                                         \
      u32 n_suffixes = 0;                                                     \
      if (serialize)                                                          \
	n_suffixes = int_manifest_header->n_suffixes;                         \
                                                                              \
      int_manifest_header->n_suffixes =                                       \
	hicn_##first##_to_##second##_32 (int_manifest_header->n_suffixes);    \
      int_manifest_header->padding =                                          \
	hicn_##first##_to_##second##_32 (int_manifest_header->padding);       \
                                                                              \
      for (unsigned i = 0; i < BITMAP_SIZE; i++)                              \
	{                                                                     \
	  int_manifest_header->request_bitmap[i] =                            \
	    hicn_##first##_to_##second##_##size (                             \
	      int_manifest_header->request_bitmap[i]);                        \
	}                                                                     \
                                                                              \
      hicn_name_suffix_t *suffix =                                            \
	(hicn_name_suffix_t *) (int_manifest_header + 1);                     \
      if (!serialize)                                                         \
	n_suffixes = int_manifest_header->n_suffixes;                         \
      for (unsigned i = 0; i < n_suffixes; i++)                               \
	{                                                                     \
	  *(suffix + i) = hicn_##first##_to_##second##_32 (*(suffix + i));    \
	}                                                                     \
    }                                                                         \
  while (0)

#define _interest_manifest_serialize(manifest, size)                          \
  _interest_manifest_serialize_deserialize (manifest, host, net, size, 1)

#define _interest_manifest_deserialize(manifest, size)                        \
  _interest_manifest_serialize_deserialize (manifest, net, host, size, 0)

static inline void
interest_manifest_serialize (interest_manifest_header_t *int_manifest_header)
{
  _interest_manifest_serialize (int_manifest_header, hicn_uword_bits);
}

static inline void
interest_manifest_deserialize (interest_manifest_header_t *int_manifest_header)
{
  _interest_manifest_deserialize (int_manifest_header, hicn_uword_bits);
}

static inline bool
interest_manifest_is_valid (interest_manifest_header_t *int_manifest_header,
			    size_t payload_length)
{
  if (int_manifest_header->n_suffixes == 0 ||
      int_manifest_header->n_suffixes > MAX_SUFFIXES_IN_MANIFEST)
    {
      return false;
    }

  hicn_uword empty_bitmap[BITMAP_SIZE] = { 0 };
  if (memcmp (empty_bitmap, int_manifest_header->request_bitmap,
	      sizeof (empty_bitmap)) == 0)
    {
      return false;
    }

  if (payload_length - sizeof (interest_manifest_header_t) !=
      int_manifest_header->n_suffixes * sizeof (u32))
    {
      return false;
    }

  return true;
}

static inline void
interest_manifest_init (interest_manifest_header_t *int_manifest_header)
{
  int_manifest_header->n_suffixes = 0;
  int_manifest_header->padding = 0;
  memset (int_manifest_header->request_bitmap, 0,
	  sizeof (int_manifest_header->request_bitmap));
}

static inline void
interest_manifest_add_suffix (interest_manifest_header_t *int_manifest_header,
			      hicn_name_suffix_t suffix)
{
  hicn_name_suffix_t *start = (hicn_name_suffix_t *) (int_manifest_header + 1);
  *(start + int_manifest_header->n_suffixes) = suffix;
  hicn_uword *request_bitmap = int_manifest_header->request_bitmap;
  bitmap_set_no_check (request_bitmap, int_manifest_header->n_suffixes);
  int_manifest_header->n_suffixes++;
}

static inline void
interest_manifest_del_suffix (interest_manifest_header_t *int_manifest_header,
			      hicn_uword pos)
{
  bitmap_unset_no_check (int_manifest_header->request_bitmap, pos);
}

static inline size_t
interest_manifest_update_bitmap (const hicn_uword *initial_bitmap,
				 hicn_uword *bitmap_to_update, size_t start,
				 size_t n, size_t max_suffixes)
{
  size_t i = start, n_ones = 0;
  while (i < n)
    {
      if (bitmap_is_set_no_check (initial_bitmap, i))
	{
	  bitmap_set_no_check (bitmap_to_update, i);
	  n_ones++;
	}
      i++;

      if (n_ones == max_suffixes)
	break;
    }

  return i;
}

#define _FIRST(h) (hicn_name_suffix_t *) (h + 1)

#define interest_manifest_foreach_suffix(header, suffix)                      \
  for (suffix = _FIRST (header) + bitmap_first_set_no_check (                 \
				    header->request_bitmap, BITMAP_SIZE);     \
       suffix - _FIRST (header) < header->n_suffixes;                         \
       suffix = _FIRST (header) +                                             \
		bitmap_next_set_no_check (header->request_bitmap,             \
					  suffix - _FIRST (header) + 1,       \
					  BITMAP_SIZE))

#endif /* HICNLIGHT_INTEREST_MANIFEST_H */
