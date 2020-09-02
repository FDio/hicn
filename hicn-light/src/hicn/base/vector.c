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
 * \file vector.c
 * \brief Implementation of resizeable static array
 */

#include <assert.h>
#include <stddef.h> // size_t
#include <stdlib.h> // calloc

#include "vector.h"

#define DEFAULT_VECTOR_SIZE 64

void
_vector_init(void ** vector_ptr, size_t elt_size, size_t init_size)
{
    assert(vector_ptr);

    if (init_size == 0)
        init_size = DEFAULT_VECTOR_SIZE;

    *vector_ptr = NULL;
    _vector_resize(vector_ptr, elt_size, init_size);

    vector_hdr_t * vh = vector_hdr(*vector_ptr);
    vh->cur_size = 0;
}

void
_vector_free(void ** vector_ptr)
{
    free(vector_hdr(*vector_ptr));
    *vector_ptr = NULL;
}

bool
_vector_resize(void ** vector_ptr, size_t elt_size, off_t pos)
{
    vector_hdr_t * vh = vector_hdr(*vector_ptr);
    /* 
     * Round the allocated size to the next power of 2 of the requested position
     */
    size_t new_elts = (pos > 0) ? next_pow2(pos) : vh->max_size * 2;

    vh = realloc(vh, VECTOR_HDRLEN + new_elts * elt_size);
    if (!vh)
        return false;
    vh->max_size = new_elts;

    /* Reassign vector pointer */
    *vector_ptr = (uint8_t*)vh + VECTOR_HDRLEN;

    return true;
}
