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
 * \file pool.c
 * \brief Implementation of fixed-size pool allocator.
 *
 * NOTE:
 *  - Ideally, we should have a single realloc per resize, that would encompass
 *  both the free indices vector and bitmap, by nesting data structures.
 * Because of the added complexity, and by lack of evidence of the need for
 * this, we currently rely on a simpler implementation.
 */

#include <assert.h>
#include <stdlib.h> // calloc

#include <hicn/util/pool.h>
#include <hicn/util/log.h>

#include <stdio.h> // XXX

void
_pool_init (void **pool_ptr, size_t elt_size, size_t init_size,
	    size_t max_size)
{
  assert (pool_ptr);
  assert (elt_size);

  init_size = next_pow2 (init_size);

  if (max_size && init_size > max_size)
    goto ERR_MAX_SIZE;

  /* The initial pool size is rounded to the next power of two */
  size_t alloc_size = next_pow2 (init_size);

  pool_hdr_t *ph = calloc (POOL_HDRLEN + alloc_size * elt_size, 1);
  if (!ph)
    goto ERR_MALLOC;

  ph->elt_size = elt_size;
  ph->alloc_size = alloc_size;
  ph->max_size = max_size;

  /* Free indices */
  off_t *free_indices;
  vector_init (free_indices, init_size, max_size);
  for (unsigned i = 0; i < init_size; i++)
    free_indices[i] = (init_size - 1) - i;
  vector_len (free_indices) = init_size;
  ph->free_indices = free_indices;

  /* Free bitmap */
  bitmap_t *fb = ph->free_bitmap;
  bitmap_init (fb, init_size, max_size);
  bitmap_set_to (fb, init_size);
  ph->free_bitmap = fb;

  *pool_ptr = (uint8_t *) ph + POOL_HDRLEN;

  return;

ERR_MALLOC:
ERR_MAX_SIZE:
  *pool_ptr = NULL;
  return;
}

void
_pool_free (void **pool_ptr)
{
  pool_hdr_t *ph = pool_hdr (*pool_ptr);
  vector_free (ph->free_indices);
  bitmap_free (ph->free_bitmap);

  free (pool_hdr (*pool_ptr));
  *pool_ptr = NULL;
}

bool
_pool_validate_id (void **pool_ptr, off_t id)
{
  pool_hdr_t *ph = pool_hdr (*pool_ptr);
  size_t pool_size = pool_get_alloc_size (*pool_ptr);
  if (id >= pool_size || !bitmap_is_unset (ph->free_bitmap, id))
    return false;

  return true;
}

void
_pool_resize (void **pool_ptr, size_t elt_size)
{
  pool_hdr_t *ph = pool_hdr (*pool_ptr);
  size_t old_size = ph->alloc_size;
  size_t new_size = old_size * 2;

  WARN ("pool_resize to %lu", new_size);

  if (ph->max_size && new_size > ph->max_size)
    goto ERR_MAX_SIZE;

  /* Double pool storage */
  ph = realloc (ph, POOL_HDRLEN + new_size * elt_size);
  if (!ph)
    goto ERR_REALLOC;
  ph->elt_size = elt_size;
  ph->alloc_size = new_size;

  /*
   * After resize, the pool will have new free indices, ranging from
   * old_size to (new_size - 1)
   */
  vector_ensure_pos (ph->free_indices, old_size);
  for (unsigned i = 0; i < old_size; i++)
    ph->free_indices[i] = new_size - 1 - i;
  vector_len (ph->free_indices) = old_size;

  /* We also need to update the bitmap */
  bitmap_ensure_pos (&(ph->free_bitmap), new_size - 1);
  bitmap_set_range (ph->free_bitmap, old_size, new_size - 1);

  /* Reassign pool pointer */
  *pool_ptr = (uint8_t *) ph + POOL_HDRLEN;

  return;

ERR_REALLOC:
ERR_MAX_SIZE:
  *pool_ptr = NULL;
  return;
}

off_t
_pool_get (void **pool_ptr, void **elt, size_t elt_size)
{
  pool_hdr_t *ph = pool_hdr (*pool_ptr);
  uint64_t l = vector_len (ph->free_indices);
  if (l == 0)
    {
      _pool_resize (pool_ptr, elt_size);
      ph = pool_hdr (*pool_ptr);
      l = vector_len (ph->free_indices);
    }
  off_t free_id = ph->free_indices[l - 1];
  vector_len (ph->free_indices)--;
  bitmap_unset (ph->free_bitmap, free_id);
  *elt = *pool_ptr + free_id * elt_size;
  return free_id;
}

void
_pool_put (void **pool_ptr, void **elt, size_t elt_size)
{
  pool_hdr_t *ph = pool_hdr (*pool_ptr);
  uint64_t l = vector_len (ph->free_indices);
  vector_ensure_pos (ph->free_indices, l);
  off_t freed_id = (*elt - *pool_ptr) / elt_size;
  ph->free_indices[l] = freed_id;
  vector_len (ph->free_indices)++;
  bitmap_set (ph->free_bitmap, freed_id);
}
