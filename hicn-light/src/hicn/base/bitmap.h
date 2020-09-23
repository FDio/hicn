/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <string.h>
#include "common.h"
#include "vector.h"

typedef uint_fast32_t bitmap_t;

#define BITMAP_WIDTH(bitmap) (sizeof((bitmap)[0]) * 8)

/**
 * @brief Allocate and initialize a bitmap
 *
 * @param[in,out] bitmap Bitmap to allocate and initialize
 * @param[in] max_size Bitmap max_size
 */
#define bitmap_init(bitmap, init_size, max_size)                        \
   vector_init(bitmap, next_pow2(init_size / BITMAP_WIDTH(bitmap)),     \
   max_size == 0 ? 0 : next_pow2(max_size / BITMAP_WIDTH(bitmap)))

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
static inline
int
bitmap_ensure_pos(bitmap_t * bitmap, off_t pos)
{
    size_t offset = pos / BITMAP_WIDTH(bitmap);
    return vector_ensure_pos(bitmap, offset);
}

/**
 * @brief Retrieve the state of the i-th bit in the bitmap.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 */
static inline
int
bitmap_get(const bitmap_t * bitmap, off_t i)
{
    size_t offset = i / BITMAP_WIDTH(bitmap);
    size_t pos = i % BITMAP_WIDTH(bitmap);
    size_t shift = BITMAP_WIDTH(bitmap) - pos - 1;
    return (bitmap[offset] >> shift) & 1;
}

/*
 * @brief Returns whether the i-th bit is set (equal to 1) in a bitmap.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 *
 * @return bool
 */
#define bitmap_is_set(bitmap, i) (bitmap_get((bitmap), (i)) == 1)
#define bitmap_is_unset(bitmap, i) (bitmap_get((bitmap), (i)) == 0)

/*
 * @brief Returns whether the i-th bit is unset (equal to 0) in a bitmap.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 *
 * @return bool
 */
static inline
void
bitmap_set(bitmap_t * bitmap, off_t i)
{
    size_t offset = i / BITMAP_WIDTH(bitmap);
    size_t pos = i % BITMAP_WIDTH(bitmap);
    size_t shift = BITMAP_WIDTH(bitmap) - pos - 1;
    bitmap[offset] |= 1ul << shift;
}

static inline
void
bitmap_unset(bitmap_t * bitmap, off_t i)
{
    size_t offset = i / BITMAP_WIDTH(bitmap);
    size_t pos = i % BITMAP_WIDTH(bitmap);
    size_t shift = BITMAP_WIDTH(bitmap) - pos - 1;
    bitmap[offset] &= ~ (1ul << shift);
}


static inline
void
bitmap_set_range(bitmap_t * bitmap, off_t from, off_t to)
{
    assert(from <= to);
    size_t offset_from = from / BITMAP_WIDTH(bitmap);
    size_t offset_to = to / BITMAP_WIDTH(bitmap);

    if (offset_to > offset_from + 1)
        memset(&bitmap[offset_from + 1], 0xFF, (offset_to - 1) * sizeof(bitmap[0]));
    for (unsigned k = from; k < (offset_from + 1) * BITMAP_WIDTH(bitmap); k++)
        bitmap_set(bitmap, k);
    for (unsigned k = offset_to * BITMAP_WIDTH(bitmap); k < to; k++)
        bitmap_set(bitmap, k);
}

#define bitmap_set_to(bitmap, to) bitmap_set_range((bitmap), 0, (to))

#define bitmap_free(bitmap) vector_free(bitmap)

#endif /* UTIL_BITMAP_H */
