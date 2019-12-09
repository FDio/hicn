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
 * \file array.h
 * \brief Fixed-size pool allocator
 */

#ifndef UTIL_POOL_H
#define UTIL_POOL_H

#include <stdint.h>

#include "bitmap.h"
#include "vector.h"

/** Local variable naming macro. */
#define _pool_var(v) _pool_##v


typedef struct {
    size_t elt_size;
    size_t max_elts;
    uint_fast32_t * free_bitmap;
    off_t * free_indices; /* vector of free indices */
} pool_hdr_t;

void _pool_init(void ** pool_ptr, size_t elt_size, size_t max_elts);
void _pool_free(void ** pool_ptr);
void _pool_resize(void ** pool_ptr, size_t elt_size);

#define POOL_HDRLEN SIZEOF_ALIGNED(pool_hdr_t)

/* This header actually prepends the actual content of the pool */
#define pool_hdr(pool) ((pool_hdr_t *)((uint8_t*)(pool) - POOL_HDRLEN))

// XXX TODO need common naming for cur_len, len, max_len
#define pool_elts(pool) \
    (pool_hdr(pool)->max_elts - vector_len((pool_hdr(pool)->free_indices)))

#define pool_init(pool, max_elts)                                       \
    _pool_init((void**)&pool, sizeof(pool[0]), max_elts);

#define pool_free(pool)                                                 \
    _pool_free((void**)&pool);

#define pool_get(pool, elt)                                             \
do {                                                                    \
    pool_hdr_t * _pool_var(ph) = pool_hdr(pool);                        \
    u64 _pool_var(l) = vector_len(_pool_var(ph)->free_indices);         \
    if (_pool_var(l) == 0)                                              \
        _pool_resize((void**)&(pool), sizeof((pool)[0]));               \
    off_t _pool_var(free_id) =                                          \
            _pool_var(ph)->free_indices[_pool_var(l) - 1];              \
    elt = (pool) + _pool_var(free_id);                                  \
    memset(&elt, 0, sizeof(elt));                                       \
} while(0)

#define pool_put(pool, elt)                                             \
do {                                                                    \
    pool_hdr_t * _pool_var(ph) = pool_hdr(pool);                        \
    u64 _pool_var(l) = vector_len(_pool_var(ph)->free_indices);         \
    vector_ensure_pos(_pool_var(ph)->free_indices, _pool_var(l));       \
    _pool_var(ph)->free_indices[_pool_var(l)] = &(elt) - (pool);        \
    vector_len(_pool_var(ph)->free_indices)++;                          \
    bitmap_set(_pool_var(ph)->free_bitmap, _pool_var(l));               \
} while(0)

#define pool_validate_id(pool, id) \
    bitmap_is_unset((pool_hdr(pool))->free_bitmap, (id))

#define pool_foreach(pool, eltp, BODY)                                  \
do {                                                                    \
    pool_hdr_t * _pool_var(ph) = pool_hdr(pool);                        \
    uint_fast32_t * _pool_var(fb) = _pool_var(ph)->free_bitmap;         \
    for(off_t _pool_var(i) = 0; _pool_var(i) < _pool_var(ph)->max_elts; \
            _pool_var(i)++) {                                           \
        if (bitmap_is_unset(_pool_var(fb), _pool_var(i)))               \
            continue;                                                   \
        eltp = (pool) + _pool_var(i);                                   \
        do { BODY; } while (0);                                         \
    }                                                                   \
} while(0)


#endif /* UTIL_POOL_H */
