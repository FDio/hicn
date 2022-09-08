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

/**
 * @brief The slab is used to store elements of the same size.
 *
 * The slab contains blocks of contiguous memory. Each block contains multiple
 * chunks. An element is stored inside a chunk and the chunk has a header with
 * a pointer to the block it belongs to.
 *
 * Blocks are stored in two doubly-linked lists: 'full' for blocks that
 * are already full, 'partial_or_empty' for blocks with available chunks. When
 * a block becomes full it is moved into the 'full' list and vice versa.
 *
 * When allocationg an element, a block is taken from the 'partial_or_empty'
 * list if such list is not empty. If empty, a new block of contiguous memory
 * is created and put in the 'partial_or_empty' list. Then, a chunk is taken
 * from the block. When releasing an element, the block it belongs to is
 * retrieved from the chunk header and used to release the chunk.
 *
 * Blocks are created with increasing capacity (i.e. number of chunks they
 * contain) such that every new block allocaion doubles the total number of
 * chunks stored in the slab.
 */

#ifndef UTIL_SLAB_H
#define UTIL_SLAB_H

#include <stddef.h>

#define SLAB_INIT_SIZE 32

/* CHUNK */

typedef struct block_s block_t;
typedef struct
{
  block_t *block; // Pointer to the block that contains the chunk
} chunk_hdr_t;

#define CHUNK_HDRLEN	 SIZEOF_ALIGNED (chunk_hdr_t)
#define chunk_hdr(chunk) ((chunk_hdr_t *) ((uint8_t *) (chunk) -CHUNK_HDRLEN))

/* BLOCK */

struct block_s
{
  void *pool;
  block_t *prev;
  block_t *next;
};

/* SLAB */

typedef struct
{
  size_t num_chunks; // Total number of chunks (from all blocks) currently
		     // stored in the slab
  size_t chunk_size;
  block_t *full;
  block_t *partial_or_empty;
} slab_t;

/* Internal API */

slab_t *_slab_create (size_t elt_size, size_t num_elts);
void *_slab_get (slab_t *slab);
void _slab_put (slab_t *slab, void *elt);

/* Public API */

/**
 * @brief Create a slab able to store elements of type 'TYPE'.
 *
 * @param[in] TYPE Type of the elements to store in the slab.
 * @param[in] SIZE Initial size of the slab, i.e. size of the initial block.
 * @return slab_t* The slab created, NULL if error.
 */
#define slab_create(TYPE, SIZE) _slab_create (sizeof (TYPE), SIZE)

/**
 * @brief Free a slab.
 *
 * @param[in] slab Slab to free.
 */
void slab_free (slab_t *slab);

/**
 * @brief Get an element from the slab.
 *
 * @param[in] TYPE Type of the elements stored in the slab.
 * @param[in] SLAB Slab to take the element from.
 * @return TYPE* Element retrieved from the slab
 */
#define slab_get(TYPE, SLAB) (TYPE *) _slab_get (SLAB)

/**
 * @brief Same as 'slab_get' but with a different signature, to avoid passing
 * the type that is instead inferred from the element.
 *
 * @param[in] SLAB Slab to take the element from.
 * @param[in, out] ELT Element retrieved from the slab.
 */
#define slab_get2(SLAB, ELT) ELT = (typeof (*(ELT)) *) _slab_get (SLAB)

/**
 * @brief Put an element back into the slab.
 *
 * @param[in] SLAB Slab to return the element to.
 * @param[in] ELT Element to put in the slab.
 */
#define slab_put(SLAB, ELT) _slab_put (SLAB, (void *) ELT)

#endif /* UTIL_SLAB_H */
