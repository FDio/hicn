/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 * \file pool.h
 * \brief Fixed-size pool allocator.
 *
 * This memory pool allocates a single block of memory that is used to
 * efficiently allocate/deallocate fixed-size blocks for high churn data
 * structures.
 *
 * Internally this data structure leverages a vector for managing elements (and
 * it thus resizeable if needed), as well as a list of free indices (in the
 * form of another vector) and a bitmap marking free indices also (for fast
 * iteration).
 *
 * The internal API manipulates a pointer to the vector that that is can be
 * seamlessly resized, and a more convenient user interface is provided through
 * macros.
 *
 * The vector of free indices is managed as a stack where elements indices are
 * retrieved from and put back to the end of the vector. In the bitmap,
 * available elements are set to 1, and unset to 0 when in use.
 *
 * The pool is not currently resized down when releasing elements.
 *
 * It is freely inspired (and simplified) from the VPP infra infrastructure
 * library.
 */

#ifndef UTIL_POOL_H
#define UTIL_POOL_H

#include <stdint.h>
#include <stdbool.h>

#include "bitmap.h"
#include "vector.h"

/* Pool header */

typedef struct {
  size_t elt_size;
  size_t alloc_size;
  size_t max_size;
  bitmap_t *free_bitmap; /* bitmap of free indices */
  off_t *free_indices;   /* vector of free indices */
} pool_hdr_t;

#define POOL_HDRLEN SIZEOF_ALIGNED(pool_hdr_t)

/* This header actually prepends the actual content of the pool. */
#define pool_hdr(pool) ((pool_hdr_t *)((uint8_t *)(pool)-POOL_HDRLEN))

/******************************************************************************/
/* Helpers */

/** Local variable naming macro. */
#define _pool_var(v) _pool_##v

/**
 * @brief Allocate and initialize a pool data structure (helper).
 *
 * @param[in,out] pool_ptr Pointer to the pool data structure.
 * @param[in] elt_size Size of elements in vector.
 * @param[in] max_size Maximum size.
 *
 * NOTE: that an empty pool might be equal to NULL.
 */
void _pool_init(void **pool_ptr, size_t elt_size, size_t init_size,
                size_t max_size);

/**
 * @brief Free a pool data structure (helper).
 *
 * @param[in] pool_ptr Pointer to the pool data structure.
 */
void _pool_free(void **pool_ptr);

/**
 * @brief Resize a pool data structure (helper).
 *
 * @param pool_ptr Pointer to the pool data structure.
 *
 * This function should only be called internally, as the resize is implicitly
 * done (if allowed by the maximum size) when the user tries to get a new slot.
 */
void _pool_resize(void **pool_ptr, size_t elt_size);

/**
 * @brief Get a free element from the pool data structure (helper).
 *
 * @param[in] pool Pointer to the pool data structure to use.
 * @param[in,out] elt Pointer to an empty element that will be used to return
 * the allocated one from the pool.
 *
 * NOTES:
 *  - The memory chunk is cleared upon attribution
 */
off_t _pool_get(void **pool, void **elt, size_t elt_size);

/**
 * @brief Put an element back into the pool data structure (helper).
 *
 * @param[in] pool_ptr Pointer to the pool data structure to use.
 * @param[in] elt Pointer to the pool element to put back.
 */
void _pool_put(void **pool, void **elt, size_t elt_size);

/**
 * @brief Validate a pool element by index (helper).
 *
 * @param[in] pool The pool data structure to use.
 * @param[in] id The index of the element to validate.
 *
 * @return bool A flag indicating whether the index is valid or not.
 */
bool _pool_validate_id(void **pool_ptr, off_t id);
/******************************************************************************/
/* Public API */

/**
 * @brief Allocate and initialize a pool data structure.
 *
 * @param[in,out] pool Pointer to the pool data structure.
 * @param[in] elt_size Size of elements in pool.
 * @param[in] max_size Maximum size.
 *
 * NOTE: that an empty pool might be equal to NULL.
 */
#define pool_init(pool, init_size, max_size) \
  _pool_init((void **)&pool, sizeof(pool[0]), init_size, max_size);

/**
 * @brief Free a pool data structure.
 *
 * @param[in] pool The pool data structure to free.
 */
#define pool_free(pool) _pool_free((void **)&pool);

/**
 * @brief Get a free element from the pool data structure.
 *
 * @param[in] pool The pool data structure to use.
 * @param[in,out] elt An empty element that will be used to return the
 * allocated one from the pool.
 *
 * NOTES:
 *  - The memory chunk is cleared upon attribution
 */
#define pool_get(pool, elt) \
  _pool_get((void **)&pool, (void **)&elt, sizeof(*elt))

/**
 * @brief Put an element back into the pool data structure.
 *
 * @param[in] pool The pool data structure to use.
 * @param[in] elt The pool element to put back.
 */
#define pool_put(pool, elt) \
  _pool_put((void **)&pool, (void **)&elt, sizeof(*elt))

/**
 * @brief Validate a pool element by index.
 *
 * @param[in] pool The pool data structure to use.
 * @param[in] id The index of the element to validate.
 *
 * @return bool A flag indicating whether the index is valid or not.
 */
#define pool_validate_id(pool, id) _pool_validate_id((void **)&pool, (id))

#define pool_get_free_indices_size(pool) \
  vector_len(pool_hdr(pool)->free_indices)

/**
 * @brief Returns the current length of the pool.
 *
 * @param[in] pool The pool data structure for which to return the length.
 *
 * @return size_t The current length of the pool.
 *
 * NOTE:
 *  - The pool length corresponds to the number of allocated elements, not the
 *  size of the pool.
 */
#define pool_len(pool) \
  (pool_hdr(pool)->alloc_size - pool_get_free_indices_size(pool))

/**
 * @brief Enumerate elements from a pool.
 *
 * @param[in] pool The pool data structure to enumerate.
 * @param[in, out] i An integer that will be used for enumeration.
 * @param[in, out] eltp A pointer to the element type that will be used for
 * enumeration.
 * @param[in] BODY Block to execute during enumeration.
 *
 * Enumeration will iteratively execute BODY with (i, eltp) corresponding
 * respectively to the index and element found in the pool.
 *
 * NOTE: i stars at 0.
 */
#define pool_enumerate(pool, i, eltp, BODY)                 \
  do {                                                      \
    pool_hdr_t *_pool_var(ph) = pool_hdr(pool);             \
    bitmap_t *_pool_var(fb) = _pool_var(ph)->free_bitmap;   \
    for ((i) = 0; (i) < _pool_var(ph)->alloc_size; (i)++) { \
      if (bitmap_is_set(_pool_var(fb), (i))) continue;      \
      eltp = (pool) + (i);                                  \
      do {                                                  \
        BODY;                                               \
      } while (0);                                          \
    }                                                       \
  } while (0)

/**
 * @brief  Iterate over elements in a pool.
 *
 * @param[in] pool The pool data structure to iterate over.
 * @param[in,out] eltp A pointer to the element type that will be used for
 * iteration.
 * @param[in] BODY Block to execute during iteration.
 *
 * Iteration will execute BODY with eltp corresponding successively to all
 * elements found in the pool. It is implemented using the more generic
 * enumeration function.
 */
#define pool_foreach(pool, eltp, BODY)                  \
  do {                                                  \
    unsigned _pool_var(i);                              \
    pool_enumerate((pool), _pool_var(i), (eltp), BODY); \
  } while (0)

#define pool_get_alloc_size(pool) pool_hdr(pool)->alloc_size

#ifdef WITH_TESTS
#define pool_get_free_indices(pool) pool_hdr(pool)->free_indices
#define pool_get_free_bitmap(pool) pool_hdr(pool)->free_bitmap
#endif /* WITH_TESTS */

#endif /* UTIL_POOL_H */
