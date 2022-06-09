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
 * \file vector.c
 * \brief Implementation of resizeable static array
 */

#include <assert.h>
#include <stddef.h> // size_t
#include <stdlib.h> // calloc
#include <stdio.h>

#include <hicn/util/vector.h>

#define DEFAULT_VECTOR_SIZE 64

int
_vector_init (void **vector_ptr, size_t elt_size, size_t init_size,
	      size_t max_size)
{
  assert (vector_ptr);
  assert (max_size == 0 || init_size < max_size);

  if (init_size == 0)
    init_size = DEFAULT_VECTOR_SIZE;

  *vector_ptr = NULL;
  int rc = _vector_resize (vector_ptr, elt_size, init_size);
  if (rc < 0)
    return -1;

  vector_hdr_t *vh = vector_hdr (*vector_ptr);
  vh->cur_size = 0;
  vh->max_size = max_size;

  return 0;
}

void
_vector_free (void **vector_ptr)
{
  free (vector_hdr (*vector_ptr));
  *vector_ptr = NULL;
}

int
_vector_resize (void **vector_ptr, size_t elt_size, off_t pos)
{
  vector_hdr_t *vh;
  size_t old_size;

  if (*vector_ptr)
    {
      vh = vector_hdr (*vector_ptr);
      old_size = vh->alloc_size;
    }
  else
    {
      vh = NULL;
      old_size = 0;
    }

  /* Round the allocated size to the next power of 2 of the requested position
   */
  size_t new_size = next_pow2 (pos);

  /* Don't grow the vector back */
  if (new_size < old_size)
    return 0;

  /* Don't exceed maximum size (for init, check is done beforehand) */
  if (vh && vh->max_size && new_size > vh->max_size)
    return -1;

  vh = realloc (vh, VECTOR_HDRLEN + new_size * elt_size);
  if (!vh)
    return -1;
  vh->alloc_size = new_size;

  /* Zero out the newly allocated memory (except headers) */
  memset ((uint8_t *) vh + VECTOR_HDRLEN + old_size * elt_size, 0,
	  (new_size - old_size) * elt_size);

  /* Reassign vector pointer */
  *vector_ptr = (uint8_t *) vh + VECTOR_HDRLEN;

  return 0;
}
