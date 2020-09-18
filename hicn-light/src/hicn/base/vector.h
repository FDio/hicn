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
 *
 * A vector is a resizeable area of contiguous memory that contains elements of
 * fixed size. It is mostly useful to serve as the basis for more advanced data
 * structures such as memory pools.
 *
 * The internal API manipulates a pointer to the vector so that it can be
 * seamlessly resized, and a more convenient user interface is provided through
 * macros.
 *
 * A vector starts at index 0, and is typed according to the elements it
 * contains. For that matter, the data structure header precedes the returned
 * pointer which corresponds to the storage area.
 *
 * A vector is by default used as a stack where an end marker is maintained and
 * new elements are pushed right after this end marker (an indication of
 * the size of the vector) after ensuring the vector is sufficiently large.
 *
 * A user should not store any pointer to vector elements as this might change
 * during reallocations, but should use indices instead.
 *
 * NOTE: a maximum size is currently not implemented.
 *
 * It is freely inspired (and simplified) from the VPP infra infrastructure
 * library.
 */

#ifndef UTIL_VECTOR_H
#define UTIL_VECTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "common.h"

/******************************************************************************/
/* Vector header */

typedef struct {
    size_t cur_size; /** Vector current size (corresponding to the highest used element). */
    size_t max_size; /** The currently allocated size. */
} vector_hdr_t;

/* Make sure elements following the header are aligned */
#define VECTOR_HDRLEN SIZEOF_ALIGNED(vector_hdr_t)

/* This header actually prepends the actual content of the vector */
#define vector_hdr(vector) ((vector_hdr_t *)((uint8_t*)vector - VECTOR_HDRLEN))

/******************************************************************************/
/* Helpers */

/** Local variable naming macro. */
#define _vector_var(v) _vector_##v

/**
 * @brief Allocate and initialize a vector data structure (helper function).
 *
 * @param[in,out] vector_ptr Vector to allocate and initialize.
 * @param[in] elt_size Size of a vector element.
 * @param[in] max_size Maximum vector size (O = unlimited).
 */
void _vector_init(void ** vector_ptr, size_t elt_size, size_t max_size);

/**
 * @brief Free a vector data structure.
 *
 * @param vector_ptr[in] Pointer to the vector data structure to free.
 */
void _vector_free(void ** vector_ptr);

/**
 * @brief Resize a vector data structure.
 *
 * @param[in] vector_ptr A pointer to the vector data structure to resize.
 * @param[in] elt_size The size of a vector element.
 * @param[in] pos The position at which the vector should be able to hold an
 * element.
 *
 * @return bool Flag indicating whether the vector has been correctly resized.
 *
 * NOTE:
 *  - The resize operation does not specify the final size of the vector but
 * instead ensure that it is large enough to hold an element at the specified
 * position. This allows the caller not to care about doing successive calls to
 * this API while the vector is growing in size.
 */
bool _vector_resize(void ** vector_ptr, size_t elt_size, off_t pos);

/**
 * @brief Ensures a vector is sufficiently large to hold an element at the
 * given position.
 *
 * @param[in] vector_ptr A pointer to the vector data structure to resize.
 * @param[in] elt_size The size of a vector element.
 * @param[in] pos The position to validate.
 *
 * @return bool Flag indicating whether the vector is available.
 *
 * NOTE:
 *  - This function should always be called before writing to a vector element
 *  to eventually make room for it (the vector will eventually be resized).
 *  - This function can fail if the vector is full and for any reason it cannot
 *  be resized.
 */
static inline
bool
_vector_ensure_pos(void ** vector_ptr, size_t elt_size, off_t pos)
{
    vector_hdr_t * vh = vector_hdr(*vector_ptr);
    if (pos >= vh->max_size)
        return _vector_resize(vector_ptr, elt_size, pos);
    return true;
}

/**
 * @brief Push an element at the end of a vector.
 *
 * @param[in] vector_ptr A pointer to the vector data structure to resize.
 * @param[in] elt_size The size of a vector element.
 * @param[in] elt The element to insert.
 *
 * NOTE:
 *  - This function ensures there is sufficient room for inserting the element,
 *  and evenutually resizes the vector to make room for it (if allowed by
 *  maximum size).
 */
static inline
bool
_vector_push(void ** vector_ptr, size_t elt_size, void * elt)
{
    vector_hdr_t * vh = vector_hdr(*vector_ptr);
    if (!_vector_ensure_pos(vector_ptr, elt_size, vh->cur_size))
        return false;
    /*(*vector_ptr)[vh->cur_size++] = elt; */
    memcpy((uint8_t*)vector_ptr + vh->cur_size++ * elt_size, elt, elt_size);
    return true;
}

/******************************************************************************/
/* Public API */

/**
 * @brief Allocate and initialize a vector data structure.
 *
 * @param[in,out] vector Vector to allocate and initialize.
 * @param[in] max_size Maximum vector size (nonzero).
 */
#define vector_init(vector, max_size) \
    _vector_init((void**)&vector, sizeof(vector[0]), max_size)

/**
 * @brief Free a vector data structure.
 *
 * @param[in] vector The vector data structure to free.
 */
#define vector_free(vector) \
    _vector_free((void**)&vector)

/**
 * @brief Resize a vector data structure.
 *
 * @param[in] vector The vector data structure to resize.
 * @param[in] pos The position at which the vector should be able to hold an
 * element.
 *
 * @return bool Flag indicating whether the vector has been correctly resized.
 *
 * NOTE:
 *  - The resize operation does not specify the final size of the vector but
 * instead ensure that it is large enough to hold an element at the specified
 * position. This allows the caller not to care about doing successive calls to
 * this API while the vector is growing in size.
 *  - If the new size is smaller than the current size, the content of the
 *  vector will be truncated.
 */
#define vector_resize(vector) _vector_resize((void**)&(vector), sizeof((vector)[0]), 0)

/**
 * @brief Ensures a vector is sufficiently large to hold an element at the
 * given position.
 *
 * @param[in] vector The vector for which to validate the position.
 * @param[in] pos The position to validate.
 *
 * NOTE:
 *  - This function should always be called before writing to a vector element
 *  to eventually make room for it (the vector will eventually be resized).
 */
#define vector_ensure_pos(vector, pos) \
    _vector_ensure_pos((void**)&(vector), sizeof((vector)[0]), pos);

/**
 * @brief Push an element at the end of a vector.
 *
 * @param[in] vector The vector in which to insert the element.
 * @param[in] elt The element to insert.
 *
 * NOTE:
 *  - This function ensures there is sufficient room for inserting the element,
 *  and evenutually resizes the vector to make room for it (if allowed by
 *  maximum size).
 */
#define vector_push(vector, elt)                                        \
do {                                                                    \
    typeof(elt) x = elt;                                                \
    _vector_push((void**)&(vector), sizeof((vector)[0]), (void*)(&x));  \
} while(0)

/**
 * @brief Returns the length of a vector.
 *
 * @param[in] vector The vector from which to get the size.
 *
 * @see vector_ensure_pos
 *
 * NOTE:
 *  - The size of the vector corresponds to the highest accessed index (for
 * example as specified in the resize operation) and not the currently
 * allocated size which will typically be bigger to amortize allocations.
 *  - A user should always call vector_ensure_pos to ensure the vector is
 *  sufficiently large to hold an element at the specified position.
 */
#define vector_len(vector) vector_hdr((vector))->cur_size

#endif /* UTIL_VECTOR_H */
