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
#define bitmap_init(bitmap, max_size) \
   vector_init(bitmap, next_pow2(max_size / BITMAP_WIDTH(bitmap)))

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
#define bitmap_ensure_pos(bitmap, pos) vector_ensure_pos(bitmap, pos / BITMAP_WIDTH(bitmap))

/**
 * @brief Retrieve the state of the i-th bit in the bitmap.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 */
#define bitmap_get(bitmap, i) (((bitmap)[(i) / BITMAP_WIDTH(bitmap)] & (1 << ((i) % BITMAP_WIDTH(bitmap)))) >> ((i) % BITMAP_WIDTH(bitmap)))

/*
 * @brief Returns whether the i-th bit is set (equal to 1) in a bitmap.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 *
 * @return bool
 */
#define bitmap_is_set(bitmap, i) (bitmap_get((bitmap), (i)) == 1)

/*
 * @brief Returns whether the i-th bit is unset (equal to 0) in a bitmap.
 *
 * @param[in] bitmap The bitmap to access.
 * @param[in] i The bit position.
 *
 * @return bool
 */
#define bitmap_is_unset(bitmap, i) (bitmap_get((bitmap), (i)) == 0)

#define bitmap_set(bitmap, i) bitmap[(i) / BITMAP_WIDTH(bitmap)] |= 1 << ((i) % BITMAP_WIDTH(bitmap))

#define bitmap_unset(bitmap, i) bitmap[(i) / BITMAP_WIDTH(bitmap)] &= ~ (1 << ((i) % BITMAP_WIDTH(bitmap)))

#define bitmap_set_to(bitmap, pos)                                      \
do {                                                                    \
    size_t offset = (pos / BITMAP_WIDTH(bitmap) + 1);                   \
    memset(bitmap, 0xFF, pos * sizeof(bitmap[0]));                      \
    size_t set_bits = offset * BITMAP_WIDTH(bitmap);                    \
    for (unsigned i = pos; i < set_bits; i++)                           \
        bitmap_unset(bitmap, i);                                        \
} while(0);

#endif /* UTIL_BITMAP_H */
