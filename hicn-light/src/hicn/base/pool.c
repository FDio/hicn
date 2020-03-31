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
 * \brief Implementation of fixed-size pool allocator
 */

#include <stdlib.h> // calloc

#include "common.h"
#include "pool.h"


/**
 * \brief Initialize the pool data structure
 * \param [in,out] pool - Pointer to the pool structure storage
 * \param [in] elt_size - Size of elements in vector
 * \param [in] max_elts - Maximum size
 *
 * Note that an empty pool might be equal to NULL
 */
void
_pool_init(void ** pool_ptr, size_t elt_size, size_t max_elts)
{
    pool_hdr_t * ph = calloc(POOL_HDRLEN + elt_size * max_elts, 1);
    if (!ph)
        abort();

    /* Free indices */
    off_t * free_indices;
    vector_init(free_indices, max_elts);

    uint_fast32_t * fb = ph->free_bitmap;
    bitmap_init(fb, max_elts);
    bitmap_set_to(fb, max_elts);

    for(unsigned i = 0; i < max_elts; i++)
        free_indices[i] = (max_elts - 1) - i;
    ph->free_indices = free_indices;

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
    size_t old_elts = ph->max_elts;
    size_t new_elts = old_elts * 2;

    /* Double pool storage */
    ph = realloc(ph, POOL_HDRLEN + new_elts * elt_size);
    if (!ph)
        abort();
    ph->max_elts = new_elts;

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
