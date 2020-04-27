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

#include <stddef.h> // size_t
#include <stdlib.h> // calloc

#include "vector.h"

void
_vector_init(void ** vector_ptr, size_t elt_size, size_t max_elts)
{
    vector_hdr_t * vh = calloc(VECTOR_HDRLEN + elt_size * max_elts, 1);
    *vector_ptr = (uint8_t*)vh - VECTOR_HDRLEN;
}

void
_vector_free(void ** vector_ptr)
{
    free(vector_hdr(*vector_ptr));
    *vector_ptr = NULL;
}

void
_vector_resize(void ** vector_ptr, size_t elt_size, off_t pos)
{
    vector_hdr_t * vh = vector_hdr(*vector_ptr);
    size_t new_elts = (pos > 0) ? next_pow2(pos) : vh->max_elts * 2;

    /* Double the allocated vector size */
    vh = realloc(vh, VECTOR_HDRLEN + new_elts * elt_size);
    if (!vh)
        abort();
    vh->max_elts = new_elts;

    /* Reassign vector pointer */
    *vector_ptr = (uint8_t*) + VECTOR_HDRLEN;
}
