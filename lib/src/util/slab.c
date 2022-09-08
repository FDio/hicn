/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <hicn/util/pool.h>
#include <hicn/util/slab.h>
#include <stdlib.h>

/* BLOCK LINKED LISTS */

static void
block_add_to_head (block_t **head_ptr, block_t *block)
{
  if (head_ptr == NULL || block == NULL)
    return;

  block->prev = NULL;
  if (*head_ptr != NULL)
    {
      block->next = *head_ptr;
      block->next->prev = block;
    }

  *head_ptr = block;
}

static block_t *
block_remove_from_head (block_t **head_ptr)
{
  if (head_ptr == NULL || *head_ptr == NULL)
    return NULL;

  block_t *old_head = *head_ptr;
  *head_ptr = old_head->next;

  if (*head_ptr != NULL)
    (*head_ptr)->prev = NULL;
  return old_head;
}

static void
block_remove (block_t **head_ptr, block_t *block)
{
  if (*head_ptr == NULL || block == NULL)
    return;

  if (block == *head_ptr)
    *head_ptr = block->next;
  if (block->next != NULL)
    block->next->prev = block->prev;
  if (block->prev != NULL)
    block->prev->next = block->next;
}

static bool
is_block_list_empty (block_t *block)
{
  return block == NULL;
}

static void
block_list_free (block_t **head)
{
  if (head == NULL || *head == NULL)
    return;

  block_t *curr_block = *head;
  while (curr_block != NULL)
    {
      block_t *next = curr_block->next;
      pool_free (curr_block->pool);
      free (curr_block);

      curr_block = next;
    }

  *head = NULL;
}

/* BLOCK */

static bool
is_block_full (block_t *block)
{
  return pool_get_free_indices_size (block->pool) == 0;
}

static void
block_set_ptr_in_chunks (block_t *block, size_t chunk_size)
{
  void *chunk = block->pool;

  // Cannot use `pool_foreach()` since it requires to know the type
  // while here we use a generic (void *)
  for (int i = 0; i < pool_get_alloc_size (block->pool); i++)
    {
      chunk_hdr_t *hdr = (chunk_hdr_t *) chunk;
      hdr->block = block;

      chunk = (uint8_t *) (chunk) + chunk_size; // Move to next chunk
    }
}

static block_t *
block_create (size_t chunk_size, size_t num_chunks)
{
  block_t *block = malloc (sizeof (block_t));
  if (block == NULL)
    return NULL;

  block->prev = block->next = NULL;
  _pool_init (&block->pool, chunk_size, num_chunks, 0);
  block_set_ptr_in_chunks (block, chunk_size);

  return block;
}

/* SLAB */

slab_t *
_slab_create (size_t elt_size, size_t num_elts)
{
  // Initialize slab
  slab_t *slab = malloc (sizeof (slab_t));
  if (slab == NULL)
    return NULL;

  *slab = (slab_t){ .num_chunks = next_pow2 (num_elts),
		    .chunk_size = CHUNK_HDRLEN + elt_size,
		    .full = NULL,
		    .partial_or_empty = NULL };

  // Add initial empty block to partial or empty list
  block_t *block = block_create (slab->chunk_size, slab->num_chunks);
  block_add_to_head (&slab->partial_or_empty, block);

  return slab;
}

void
slab_free (slab_t *slab)
{
  block_list_free (&slab->full);
  block_list_free (&slab->partial_or_empty);
  free (slab);
}

void *
_slab_get (slab_t *slab)
{
  // Create new empty block if none with available chunks
  if (is_block_list_empty (slab->partial_or_empty))
    {
      block_t *block = block_create (slab->chunk_size, slab->num_chunks);
      block_add_to_head (&slab->partial_or_empty, block);

      slab->num_chunks *= 2; // Grow size exponentially
    }

  // Get chunck from first block in 'partial_or_empty' list
  void *chunk;
  _pool_get (&slab->partial_or_empty->pool, &chunk, slab->chunk_size);

  // If the current block (i.e. head of 'partial_or_empty' list) if full,
  // move it to the 'full' list
  if (is_block_full (slab->partial_or_empty))
    {
      block_t *block = block_remove_from_head (&slab->partial_or_empty);
      block_add_to_head (&slab->full, block);
    }

  return (uint8_t *) chunk + CHUNK_HDRLEN;
}

void
_slab_put (slab_t *slab, void *chunk)
{
  // Get which block the chunk (that we want to release) belong to
  chunk_hdr_t *hdr = chunk_hdr (chunk);
  block_t *block = hdr->block;

  // Put chunk back into block
  bool is_full = is_block_full (block);
  _pool_put (&block->pool, (void *) &hdr, slab->chunk_size);

  // If the block was previously full, move it to 'partial_or_empty' list
  if (is_full)
    {
      block_remove (&slab->full, block);
      block_add_to_head (&slab->partial_or_empty, block);
    }
}