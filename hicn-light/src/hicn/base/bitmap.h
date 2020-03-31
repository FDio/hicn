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

#define BITMAP_WIDTH(bitmap) (sizeof((bitmap)[0]) * 8)

#define bitmap_init(bitmap, size) \
   vector_init(bitmap, next_pow2(size / BITMAP_WIDTH(bitmap)))

#define bitmap_ensure_pos(bitmap, pos) vector_ensure_pos(bitmap, pos / BITMAP_WIDTH(bitmap))

#define bitmap_get(bitmap, i) ((bitmap)[(i) / BITMAP_WIDTH(bitmap)] & (1 << ((i) % BITMAP_WIDTH(bitmap))))

#define bitmap_is_set(bitmap, i) (bitmap_get((bitmap), (i)) == 1)

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
