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

/**
 * \file bitmap.h
 * \brief Bitmap
 *
 * A bitmap is implemented as a wrapper over a vector made of bit elements
 */

#ifndef UTIL_BITMAP_H
#define UTIL_BITMAP_H

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h> // MIN, MAX

#include <hicn/common.h>
#include <hicn/util/vector.h>

typedef hicn_uword bitmap_t;

#define WORD_WIDTH (sizeof (bitmap_t) * 8)

#define WORD_WIDTH	     (sizeof (bitmap_t) * 8)
#define BITMAP_WIDTH(bitmap) (sizeof ((bitmap)[0]) * 8)
#define BITMAP_INVALID_INDEX ((uint32_t) (~0))

static inline int
get_lowest_set_bit_index (hicn_uword w)
{
  return hicn_uword_bits > 32 ? __builtin_ctzll (w) : __builtin_ctz (w);
}

/**
 * @brief Allocate and initialize a bitmap
 *
 * @param[in,out] bitmap Bitmap to allocate and initialize
 * @param[in] max_size Bitmap max_size
 */
#define bitmap_init(bitmap, init_size, max_size)                              \
  vector_init (                                                               \
    bitmap, next_pow2 ((init_size) / BITMAP_WIDTH (bitmap)),                  \
    max_size == 0 ? 0 : next_pow2 ((max_size) / BITMAP_WIDTH (bitmap)))

/*
 * @brief Ensures a bitmap is sufficiently large to hold an element at the
 * given position.
 *
 * @param[in] bitmap The bitmap for which to validate the position.
 * @param[in] pos The position to validate.
 *
 * NOTE:
 *  - This function should always be called before writing to a bitmap element
 *  to eventually make room for it (the bitmap will eventually be resized).
 */
static inline int
bitmap_ensure_pos (bitmap_t **bitmap, off_t pos)
{
  size_t offset = pos / BITMAP_WIDTH (*bitmap);
  return vector_ensure_pos (*bitmap, offset);
}

/**
 * @brief Returns the allocated size of a bitmap.
 *
 * @see listener_table_get_by_id
 */
#define bitmap_get_alloc_size(bitmap) vector_get_alloc_size (bitmap)

/**
 * @brief Retrieve the state of the i-th bit in the bitmap.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 */
static inline int
_bitmap_get (const bitmap_t *bitmap, off_t i)
{
  size_t offset = i / BITMAP_WIDTH (bitmap);
  assert (offset < bitmap_get_alloc_size (bitmap));
  size_t pos = i % BITMAP_WIDTH (bitmap);
  return (bitmap[offset] >> pos) & 1;
}

/**
 * @brief Retrieve the state of the i-th bit in the bitmap.
 * Does not sanity check the position.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 */
static inline int
_bitmap_get_no_check (const bitmap_t *bitmap, off_t i)
{
  size_t offset = i / BITMAP_WIDTH (bitmap);
  size_t pos = i % BITMAP_WIDTH (bitmap);
  return (bitmap[offset] >> pos) & 1;
}

/*
 * @brief Returns whether the i-th bit is set (equal to 1) in a bitmap.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 *
 * @return bool
 */
#define bitmap_is_set(bitmap, i)   (_bitmap_get ((bitmap), (i)) == 1)
#define bitmap_is_unset(bitmap, i) (_bitmap_get ((bitmap), (i)) == 0)

#define bitmap_is_set_no_check(bitmap, i)                                     \
  (_bitmap_get_no_check ((bitmap), (i)) == 1)
#define bitmap_is_unset_no_check(bitmap, i)                                   \
  (_bitmap_get_no_check ((bitmap), (i)) == 0)

/*
 * @brief Returns whether the i-th bit is unset (equal to 0) in a bitmap.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 *
 * @return bool
 */
#define bitmap_set(bitmap, i) _bitmap_set ((bitmap_t **) &bitmap, i, 1)
#define bitmap_set_no_check(bitmap, i)                                        \
  _bitmap_set ((bitmap_t **) &bitmap, i, 0)

/*
 * @brief Returns whether the i-th bit is unset (equal to 0) in a bitmap
 * (helper).
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 *
 * @return bool
 */
static inline int
_bitmap_set (bitmap_t **bitmap_ptr, off_t i, int check)
{
  if (check && bitmap_ensure_pos (bitmap_ptr, i) < 0)
    return -1;

  bitmap_t *bitmap = *bitmap_ptr;
  size_t offset = i / BITMAP_WIDTH (bitmap);
  size_t pos = i % BITMAP_WIDTH (bitmap);

  bitmap[offset] |= (bitmap_t) 1 << pos;
  return 0;
}

#define bitmap_unset(bitmap, i)		 _bitmap_unset (bitmap, i, 1)
#define bitmap_unset_no_check(bitmap, i) _bitmap_unset (bitmap, i, 0)

static inline int
_bitmap_unset (bitmap_t *bitmap, off_t i, int check)
{
  if (check && bitmap_ensure_pos (&bitmap, i) < 0)
    return -1;
  size_t offset = i / BITMAP_WIDTH (bitmap);
  size_t pos = i % BITMAP_WIDTH (bitmap);
  bitmap[offset] &= ~(1ul << pos);
  return 0;
}

static inline int
bitmap_set_range (bitmap_t *bitmap, off_t from, off_t to)
{
  assert (from <= to);
  ssize_t offset_from = from / BITMAP_WIDTH (bitmap);
  ssize_t offset_to = to / BITMAP_WIDTH (bitmap);
  size_t pos_from = from % BITMAP_WIDTH (bitmap);
  size_t pos_to = to % BITMAP_WIDTH (bitmap);

  /*
   * First block initialization is needed if <from> is not aligned with the
   * bitmap element size or if to is within the same one.
   */
  if ((pos_from != 0) ||
      ((offset_to == offset_from) && (pos_to != BITMAP_WIDTH (bitmap) - 1)))
    {
      size_t from_end = MIN (to, (offset_from + 1) * BITMAP_WIDTH (bitmap));
      for (size_t k = from; k < from_end; k++)
	{
	  if (bitmap_set (bitmap, k) < 0)
	    goto END;
	}
    }

  /*
   * Second block is needed if <to> is not aligned with the bitmap element
   * size
   */
  if ((pos_to != BITMAP_WIDTH (bitmap) - 1) && (offset_to != offset_from))
    {
      size_t to_start = MAX (from, offset_to * BITMAP_WIDTH (bitmap));
      for (size_t k = to_start; k < (size_t) to; k++)
	{
	  if (bitmap_set (bitmap, k) < 0)
	    goto END;
	}
    }

  if (pos_from != 0)
    offset_from += 1;
  if (pos_to != BITMAP_WIDTH (bitmap) - 1)
    offset_to -= 1;

  /*
   * We need to cover both elements at position offset_from and offset_to
   * provided that offset_from is not bigger
   */
  if (offset_to >= offset_from)
    {
      memset (&bitmap[offset_from], 0xFF,
	      (offset_to - offset_from + 1) * sizeof (bitmap[0]));
    }

  return 0;

END:
  return -1;
}

#define bitmap_set_to(bitmap, to) bitmap_set_range ((bitmap), 0, (to))

#define bitmap_free(bitmap) vector_free (bitmap)

static inline hicn_uword
bitmap_next_set_no_check (const bitmap_t *bitmap, hicn_uword i, size_t length)
{
  hicn_uword pos = i / WORD_WIDTH;
  hicn_uword offset = i % WORD_WIDTH;
  hicn_uword tmp;
  hicn_uword mask = ~((1ULL << offset) - 1);

  if (pos < length)
    {
      // This will zeroes all bits < i
      tmp = bitmap[pos] & mask;
      if (tmp)
	return get_lowest_set_bit_index (tmp) + pos * WORD_WIDTH;

      for (pos += 1; pos < length; pos++)
	{
	  tmp = bitmap[pos];
	  if (tmp)
	    return get_lowest_set_bit_index (tmp) + pos * WORD_WIDTH;
	}
    }

  return BITMAP_INVALID_INDEX;
}

static inline hicn_uword
bitmap_next_set (const bitmap_t *bitmap, hicn_uword i)
{
  return bitmap_next_set_no_check (bitmap, i, vector_get_alloc_size (bitmap));
}

static inline hicn_uword
bitmap_next_unset_no_check (const bitmap_t *bitmap, hicn_uword i,
			    size_t length)
{
  hicn_uword pos = i / WORD_WIDTH;
  hicn_uword offset = i % WORD_WIDTH;
  hicn_uword tmp;
  hicn_uword mask = ~((1ULL << offset) - 1);

  if (pos < length)
    {
      // This will zeroes all bits < i
      tmp = ~bitmap[pos] & mask;
      if (tmp)
	return get_lowest_set_bit_index (tmp) + pos * WORD_WIDTH;

      for (pos += 1; pos < length; pos++)
	{
	  tmp = ~bitmap[pos];
	  if (tmp)
	    return get_lowest_set_bit_index (tmp) + pos * WORD_WIDTH;
	}
    }
  return BITMAP_INVALID_INDEX;
}

static inline hicn_uword
bitmap_next_unset (const bitmap_t *bitmap, hicn_uword i)
{
  return bitmap_next_unset_no_check (bitmap, i,
				     vector_get_alloc_size (bitmap));
}

#define bitmap_first_set(bitmap) bitmap_next_set (bitmap, 0)
#define bitmap_first_set_no_check(bitmap, size)                               \
  bitmap_next_set_no_checks (bitmap, 0, size)

#define bitmap_first_unset(bitmap) bitmap_next_unset (bitmap, 0)
#define bitmap_first_unset_no_check(bitmap, size)                             \
  bitmap_next_unset_no_checks (bitmap, 0, size)

static inline void
bitmap_print (const bitmap_t *bitmap, size_t n_words)
{
  for (size_t word = 0; word < n_words; word++)
    {
      for (int bit = sizeof (hicn_uword) - 1; bit >= 0; bit--)
	(bitmap_is_set_no_check (&bitmap[word], bit)) ? printf ("1") :
							      printf ("0");
    }
}

#endif /* UTIL_BITMAP_H */
