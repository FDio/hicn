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

#include <stdint.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>

#include "../common.h"

/******************************************************************************/
/* Vector header */

typedef struct
{
  size_t cur_size;   /** Vector current size (corresponding to the highest used
			element). */
  size_t alloc_size; /** The currently allocated size. */
  size_t max_size;   /** The maximum allowed size (0 = no limit) */
} vector_hdr_t;

/* Make sure elements following the header are aligned */
#define VECTOR_HDRLEN SIZEOF_ALIGNED (vector_hdr_t)

/* This header actually prepends the actual content of the vector */
#define vector_hdr(vector)                                                    \
  ((vector_hdr_t *) ((uint8_t *) vector - VECTOR_HDRLEN))

/******************************************************************************/
/* Helpers */

/** Local variable naming macro. */
#define _vector_var(v) _vector_##v

/**
 * @brief Allocate and initialize a vector data structure (helper function).
 *
 * @param[in,out] vector_ptr Vector to allocate and initialize.
 * @param[in] elt_size Size of a vector element.
 * @param[in] init_size Initial vector size.
 * @param[in] max_size Maximum vector size (O = unlimited).
 * @return int 0 if successful, -1 otherwise
 */
int _vector_init (void **vector_ptr, size_t elt_size, size_t init_size,
		  size_t max_size);

/**
 * @brief Free a vector data structure.
 *
 * @param vector_ptr[in] Pointer to the vector data structure to free.
 */
void _vector_free (void **vector_ptr);

/**
 * @brief Resize a vector data structure.
 *
 * @param[in] vector_ptr A pointer to the vector data structure to resize.
 * @param[in] elt_size The size of a vector element.
 * @param[in] pos The position at which the vector should be able to hold an
 * element.
 *
 * @return int Flag indicating whether the vector has been correctly resized.
 *
 * NOTE:
 *  - The resize operation does not specify the final size of the vector but
 * instead ensure that it is large enough to hold an element at the specified
 * position. This allows the caller not to care about doing successive calls to
 * this API while the vector is growing in size.
 */
int _vector_resize (void **vector_ptr, size_t elt_size, off_t pos);

/**
 * @brief Ensures a vector is sufficiently large to hold an element at the
 * given position.
 *
 * @param[in] vector_ptr A pointer to the vector data structure to resize.
 * @param[in] elt_size The size of a vector element.
 * @param[in] pos The position to validate.
 *
 * @return int Flag indicating whether the vector is available.
 *
 * NOTE:
 *  - This function should always be called before writing to a vector element
 *  to eventually make room for it (the vector will eventually be resized).
 *  - This function can fail if the vector is full and for any reason it cannot
 *  be resized.
 */
static inline int
_vector_ensure_pos (void **vector_ptr, size_t elt_size, off_t pos)
{
  vector_hdr_t *vh = vector_hdr (*vector_ptr);
  if (pos >= (off_t) vh->alloc_size)
    return _vector_resize (vector_ptr, elt_size, pos + 1);
  return 0;
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
static inline int
_vector_push (void **vector_ptr, size_t elt_size, void *elt)
{
  vector_hdr_t *vh = vector_hdr (*vector_ptr);
  if (_vector_ensure_pos (vector_ptr, elt_size, vh->cur_size) < 0)
    return -1;

  /* Always get header after a potential resize */
  vh = vector_hdr (*vector_ptr);
  memcpy ((uint8_t *) *vector_ptr + vh->cur_size * elt_size, elt, elt_size);
  vh = vector_hdr (*vector_ptr);
  vh->cur_size++;
  return 0;
}

/**
 * @brief Remove all the occurrencies of an element from the vector.
 * The order of the elements is NOT maintained.
 *
 * @param[in, out] vector The vector data structure to resize
 * @param[in] elt_size The size of a vector element
 * @param[in] elt The element to remove
 * @return int Number of elemets (equal to 'elt') removed from the vector
 */
static inline int
_vector_remove_unordered (void *vector, size_t elt_size, void *elt)
{
  size_t num_removed = 0;
  vector_hdr_t *vh = vector_hdr (vector);
  for (size_t i = 0; i < vector_hdr (vector)->cur_size; i++)
    {
      if (memcmp ((uint8_t *) vector + i * elt_size, elt, elt_size) == 0)
	{
	  vh->cur_size--;
	  // Copy last element to current position (hence order is not
	  // maintained)
	  memcpy ((uint8_t *) vector + i * elt_size,
		  (uint8_t *) vector + vh->cur_size * elt_size, elt_size);
	  num_removed++;
	}
    }
  return (int) num_removed;
}

/**
 * @brief Get the element at the specified position and store in 'elt'.
 *
 * @param[in] vector Pointer to the vector data structure to use
 * @param[in] pos Position of the element to retrieve
 * @param[in] elt_size The size of a vector element
 * @param[in] elt The element where the result is stored
 * @return int 0 if successful, -1 otherwise
 */
static inline int
_vector_get (void *vector, off_t pos, size_t elt_size, void *elt)
{
  vector_hdr_t *vh = vector_hdr (vector);
  if ((size_t) pos >= vh->alloc_size)
    return -1;

  memcpy (elt, (uint8_t *) vector + pos * elt_size, elt_size);
  return 0;
}

/**
 * @brief Check if specified element is present in vector.
 *
 * @param[in] vector Pointer to the vector data structure to use
 * @param[in] elt_size The size of a vector element
 * @param[in] elt The element to search for
 * @return true If specified element is contained in the vector
 * @return false
 */
static inline bool
_vector_contains (void *vector, size_t elt_size, void *elt)
{
  for (size_t i = 0; i < vector_hdr (vector)->cur_size; i++)
    {
      if (memcmp ((uint8_t *) vector + i * elt_size, elt, elt_size) == 0)
	return true;
    }

  return false;
}

/**
 * @brief Remove the element at the specified position from the vector.
 * Relative element order is preserved by shifting left the elements after the
 * target.
 *
 * @param[in, out] vector Pointer to the vector data structure to use
 * @param[in] elt_size The size of a vector element
 * @param[in] pos Position of the element to remove
 * @return int 0 if successful, -1 otherwise
 */
static inline int
_vector_remove_at (void **vector_ptr, size_t elt_size, off_t pos)
{
  vector_hdr_t *vh = vector_hdr (*vector_ptr);
  if ((size_t) pos >= vh->cur_size)
    return -1;

  // Shift backward by one position all the elements after the one specified
  memmove ((uint8_t *) (*vector_ptr) + pos * elt_size,
	   (uint8_t *) (*vector_ptr) + (pos + 1) * elt_size,
	   (vh->cur_size - 1 - pos) * elt_size);
  vh->cur_size--;

  return 0;
}

/******************************************************************************/
/* Public API */

/**
 * @brief Allocate and initialize a vector data structure.
 *
 * @param[in,out] vector Vector to allocate and initialize.
 * @param[in] init_size Initial vector size.
 * @param[in] max_size Maximum vector size (nonzero).
 *
 * NOTE:
 *  - Allocated memory is set to 0 (used by bitmap)
 */

#define vector_init(vector, init_size, max_size)                              \
  _vector_init ((void **) &vector, sizeof (vector[0]), init_size, max_size)

/**
 * @brief Free a vector data structure.
 *
 * @param[in] vector The vector data structure to free.
 */
#define vector_free(vector) _vector_free ((void **) &vector)

/**
 * @brief Resize a vector data structure.
 *
 * @param[in] vector The vector data structure to resize.
 * @param[in] pos The position at which the vector should be able to hold an
 * element.
 *
 * @return int Flag indicating whether the vector has been correctly resized.
 *
 * NOTE:
 *  - The resize operation does not specify the final size of the vector but
 * instead ensure that it is large enough to hold an element at the specified
 * position. This allows the caller not to care about doing successive calls to
 * this API while the vector is growing in size.
 *  - If the new size is smaller than the current size, the content of the
 *  vector will be truncated.
 * - Newly allocated memory is set to 0 (used by bitmap)
 */
#define vector_resize(vector)                                                 \
  _vector_resize ((void **) &(vector), sizeof ((vector)[0]), 0)

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
#define vector_ensure_pos(vector, pos)                                        \
  _vector_ensure_pos ((void **) &(vector), sizeof ((vector)[0]), pos);

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
#define vector_push(vector, elt)                                              \
  ({                                                                          \
    typeof (elt) _vector_var (x) = elt;                                       \
    _vector_push ((void **) &(vector), sizeof ((vector)[0]),                  \
		  (void *) (&_vector_var (x)));                               \
  })

#define vector_at(vector, pos)                                                \
  ({                                                                          \
    assert ((size_t) pos < vector_hdr (vector)->cur_size);                    \
    (vector)[(pos)];                                                          \
  })

#define vector_set(vector, pos, elt)                                          \
  ({                                                                          \
    assert (pos < vector_hdr (vector)->cur_size);                             \
    (vector)[(pos)] = elt;                                                    \
  })

/**
 * @brief Clear the vector content, i.e. new pushes will insert starting from
 * position 0.
 *
 * @param[in, out] vector The vector to reset
 */
#define vector_reset(vector) (vector_len (vector) = 0)

/**
 * @brief Get the element at the specified position and store in 'elt'.
 *
 * @param[in] vector The vector data structure to use
 * @param[in] pos Position of the element to retrieve
 * @param[in] elt The element where the result is stored
 * @return int 0 if successful, -1 otherwise
 */
#define vector_get(vector, pos, elt)                                          \
  _vector_get ((void *) (vector), (pos), sizeof ((vector)[0]),                \
	       (void *) (&elt));

/**
 * @brief Check if specified element is present in vector.
 *
 * @param[in] vector The vector data structure to use
 * @param[in] elt The element to search for
 * @return true If specified element is contained in the vector
 * @return false
 */
#define vector_contains(vector, elt)                                          \
  ({                                                                          \
    typeof (elt) _vector_var (x) = elt;                                       \
    _vector_contains ((void *) (vector), sizeof ((vector)[0]),                \
		      (void *) (&_vector_var (x)));                           \
  })

/**
 * @brief Remove the element at the specified position from the vector.
 * Relative element order is preserved by shifting left the elements after the
 * target.
 *
 * @param[in, out] vector The vector data structure to use
 * @param[in] pos Position of the element to remove
 * @return int 0 if successful, -1 otherwise
 */
#define vector_remove_at(vector, pos)                                         \
  _vector_remove_at ((void **) &(vector), sizeof ((vector)[0]), (pos))

/**
 * @brief Remove all the occurrencies of an element from the vector.
 * The order of the elements is NOT maintained.
 *
 * @param[in, out] vector The vector data structure to resize
 * @param[in] elt The element to remove
 * @return int Number of elemets (equal to 'elt') removed from the vector
 */
#define vector_remove_unordered(vector, elt)                                  \
  ({                                                                          \
    typeof (elt) x = elt;                                                     \
    _vector_remove_unordered ((void *) (vector), sizeof ((vector)[0]),        \
			      (void *) (&x));                                 \
  })

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
#define vector_len(vector) vector_hdr (vector)->cur_size

/**
 * @brief Returns the allocated size of a vector.
 */
#define vector_get_alloc_size(vector) vector_hdr (vector)->alloc_size

/**
 * @brief Iterate over elements in a vector.
 *
 * @param[in] pool The vector data structure to iterate over
 * @param[in, out] eltp A pointer to the element that will be used for
 * iteration
 * @param[in] BODY Block to execute during iteration
 *
 * @note Iteration will execute BODY with eltp corresponding successively to
 * all elements found in the vector. It is implemented using the more generic
 * enumeration function.
 */
#define vector_foreach(vector, eltp, BODY)                                    \
  ({                                                                          \
    unsigned _vector_var (i);                                                 \
    vector_enumerate ((vector), _vector_var (i), (eltp), BODY);               \
  })

/**
 * @brief Helper function used by vector_foreach().
 */
#define vector_enumerate(vector, i, eltp, BODY)                               \
  ({                                                                          \
    for ((i) = 0; (i) < vector_len (vector); (i)++)                           \
      {                                                                       \
	eltp = (vector) + (i);                                                \
	{                                                                     \
	  BODY;                                                               \
	}                                                                     \
      }                                                                       \
  })

#endif /* UTIL_VECTOR_H */
