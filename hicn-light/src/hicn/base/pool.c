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
 * \file pool.c
 * \brief Implementation of fixed-size pool allocator.
 * 
 * NOTE:
 *  - Ideally, we should have a single realloc per resize, that would encompass
 *  both the free indices vector and bitmap, by nesting data structures. Because
 *  of the added complexity, and by lack of evidence of the need for this, we
 *  currently rely on a simpler implementation.
 */

#include <assert.h>
#include <stdlib.h> // calloc

#include "common.h"
#include "pool.h"

void
_pool_init(void ** pool_ptr, size_t elt_size, size_t max_size)
{
    assert(pool_ptr);
    assert(elt_size);

    pool_hdr_t * ph = calloc(POOL_HDRLEN + elt_size * max_size, 1);
    if (!ph) {
        *pool_ptr = NULL;
        return;
    }

    ph->elt_size = elt_size;
    ph->max_size = max_size;

    /* Free indices */
    off_t * free_indices;
    vector_init(free_indices, max_size);
    for(unsigned i = 0; i < max_size; i++)
        free_indices[i] = (max_size - 1) - i;
    vector_len(free_indices) = max_size;
    ph->free_indices = free_indices;

    /* Free bitmap */
    uint_fast32_t * fb = ph->free_bitmap;
    bitmap_init(fb, max_size);
    bitmap_set_to(fb, max_size);
    ph->free_bitmap = fb;

    *pool_ptr = (uint8_t*)ph + POOL_HDRLEN;
}

void
_pool_free(void ** pool_ptr)
{
    free(pool_hdr(*pool_ptr));
    *pool_ptr = NULL;
}

void
_pool_resize(void ** pool_ptr, size_t elt_size)
{
    pool_hdr_t * ph = pool_hdr(*pool_ptr);
    size_t old_elts = ph->max_size;
    size_t new_elts = old_elts * 2;

    /* Double pool storage */
    ph = realloc(ph, POOL_HDRLEN + new_elts * elt_size);
    if (!ph) {
        *pool_ptr = NULL;
        return;
    }
    ph->elt_size = elt_size;
    ph->max_size = new_elts;

    /*
     * After resize, the pool will have old_elts free indices, ranging from
     * old_elts to (new_elts - 1)
     */
    off_t * free_indices = ph->free_indices;
    vector_ensure_pos(free_indices, old_elts);
    for (unsigned i = 0; i < old_elts; i++)
        free_indices[i] = new_elts - 1 - i;

    /* Reassign pool pointer */
    *pool_ptr = (uint8_t*)ph + POOL_HDRLEN;
}

void
_pool_get(void ** pool_ptr, void ** elt, size_t elt_size)
{
    pool_hdr_t * ph = pool_hdr(*pool_ptr);
    uint64_t l = vector_len(ph->free_indices);
    if (l == 0)
        _pool_resize(pool_ptr, elt_size);
    off_t free_id = ph->free_indices[l - 1];
    vector_len(ph->free_indices)--;
    *elt = *pool_ptr + free_id;
    memset(*elt, 0, sizeof(elt));
}

void
_pool_put(void ** pool_ptr, void ** elt, size_t elt_size)
{
    pool_hdr_t * ph = pool_hdr(*pool_ptr);
    uint64_t l = vector_len(ph->free_indices);
    vector_ensure_pos(ph->free_indices, l);
    ph->free_indices[l] = *elt - *pool_ptr;
    vector_len(ph->free_indices)++;
    bitmap_set(ph->free_bitmap, l);
}
