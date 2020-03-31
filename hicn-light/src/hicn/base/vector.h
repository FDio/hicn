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
 * \file vector.h
 * \brief Resizeable static array
 */

#ifndef UTIL_VECTOR_H
#define UTIL_VECTOR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "common.h"

/** Local variable naming macro. */
#define _vector_var(v) _vector_##v

typedef struct {
    size_t num_elts;
    size_t max_elts;
} vector_hdr_t;

void _vector_init(void ** vector_ptr, size_t elt_size, size_t max_elts);
void _vector_free(void ** vector_ptr);
void _vector_resize(void ** vector_ptr, size_t elt_size, off_t pos);

/* Make sure elements following the header are aligned */
#define VECTOR_HDRLEN SIZEOF_ALIGNED(vector_hdr_t)

/* This header actually prepends the actual content of the vector */
#define vector_hdr(vector) ((vector_hdr_t *)((uint8_t*)vector - VECTOR_HDRLEN))

#define vector_init(vector, max_elts) \
    _vector_init((void**)&vector, sizeof(vector[0]), max_elts)

#define vector_free(vector) \
    _vector_free(&vector)

#define vector_len(vector) (vector_hdr(vector)->num_elts)

#define vector_resize(vector) _vector_resize((void**)&(vector), sizeof((vector)[0]), 0)

#define vector_ensure_pos(vector, pos)                                          \
do {                                                                            \
    if ((pos) >= vector_len(vector))                                            \
        _vector_resize((void**)&(vector), sizeof((vector)[0]), pos);            \
} while(0)

#define vector_push(vector, elt)                                                \
do {                                                                            \
    vector_ensure_pos(vector_len(vector));                                      \
    vector[vector_len(vector)++] = elt;                                         \
} while(0)

#endif /* UTIL_VECTOR_H */
