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
 * \file ring.h
 * \brief Fixed-size pool allocator.
 */

#ifndef UTIL_RING_H
#define UTIL_RING_H

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>  // MIN
#include <sys/types.h>

#include <stdio.h>  // XXX debug

#include "common.h"

/******************************************************************************/
/* Ring header */

typedef struct {
  size_t roff;
  size_t woff;
  size_t size;
  size_t max_size;
} ring_hdr_t;

/* Make sure elements following the header are aligned */
#define RING_HDRLEN SIZEOF_ALIGNED(ring_hdr_t)

/* This header actually prepends the actual content of the vector */
#define ring_hdr(ring) ((ring_hdr_t *)((uint8_t *)ring - RING_HDRLEN))

/******************************************************************************/
/* Helpers */

/** Local variable naming macro. */
#define _ring_var(v) _ring_##v

/**
 * @brief Allocate and initialize a ring data structure (helper function).
 *
 * @param[in,out] ring_ptr Ring buffer to allocate and initialize.
 * @param[in] elt_size Size of a ring element.
 * @param[in] max_size Maximum vector size (O = unlimited).
 */
void _ring_init(void **ring_ptr, size_t elt_size, size_t max_size);

/**
 * @brief Free a ring data structure.
 *
 * @param ring_ptr[in] Pointer to the ring data structure to free.
 */
void _ring_free(void **ring_ptr);

static inline int _ring_add(void **ring_ptr, size_t elt_size, void *eltp) {
  assert(*ring_ptr);
  ring_hdr_t *rh = ring_hdr(*ring_ptr);

  /* We always write ! */
  memcpy((uint8_t *)*ring_ptr + rh->woff * elt_size, eltp, elt_size);
  rh->woff++;
  if (rh->woff == rh->max_size) rh->woff = 0;
  if (rh->size < rh->max_size) {
    rh->size++;
  } else {
    /* One packet was dropped */
    rh->roff++;
    if (rh->roff == rh->max_size) rh->roff = 0;
  }
  return 0;
}

static inline unsigned _ring_get_fullness(void **ring_ptr) {
  assert(*ring_ptr);
  ring_hdr_t *rh = ring_hdr(*ring_ptr);
  return rh->size * 100 / rh->max_size;
}

static inline unsigned _ring_is_full(void **ring_ptr) {
  assert(*ring_ptr);
  ring_hdr_t *rh = ring_hdr(*ring_ptr);
  return rh->size == rh->max_size;
}

static inline size_t _ring_get_size(void **ring_ptr) {
  assert(*ring_ptr);
  ring_hdr_t *rh = ring_hdr(*ring_ptr);
  return rh->size;
}

static inline int _ring_advance(void **ring_ptr, unsigned n) {
  assert(*ring_ptr);
  ring_hdr_t *rh = ring_hdr(*ring_ptr);
  assert(n <= rh->size);

  rh->roff += n;
  rh->size -= n;
  while (rh->roff >= rh->max_size) rh->roff -= rh->max_size;
  return 0;
}

static inline int _ring_get(void **ring_ptr, size_t elt_size, unsigned i,
                            void *eltp) {
  assert(*ring_ptr);
  ring_hdr_t *rh = ring_hdr(*ring_ptr);
  assert(i <= rh->size);
  size_t pos = rh->roff + i;
  if (pos >= rh->max_size) pos -= rh->max_size;
  memcpy(eltp, (uint8_t *)*ring_ptr + pos * elt_size, elt_size);
  return 0;
}

/******************************************************************************/
/* Public API */

/**
 * @brief Allocate and initialize a ring data structure.
 *
 * @param[in,out] ring Ring to allocate and initialize.
 * @param[in] max_size Maximum ring size (nonzero).
 *
 * NOTE:
 *  - Allocated memory is set to 0 (used by bitmap)
 */

#define ring_init(RING, MAX_SIZE) \
  _ring_init((void **)&(RING), sizeof((RING)[0]), (MAX_SIZE))

#define ring_free(RING) _ring_free((void **)&(RING))

#define ring_get_fullness(RING) _ring_get_fullness((void **)&(RING))

#define ring_is_full(RING) _ring_is_full((void **)&(RING))

#define ring_get_size(RING) _ring_get_size((void **)&(RING))

#define ring_add(RING, ELT) _ring_add((void **)&(RING), sizeof(RING[0]), ELT)

#define ring_add_value(RING, VALUE)                              \
  do {                                                           \
    typeof(VALUE) _ring_var(v) = VALUE;                          \
    _ring_add((void **)&(RING), sizeof(RING[0]), &_ring_var(v)); \
  } while (0)

#define ring_advance(RING, N) _ring_advance((void **)&(RING), (N))

#define ring_get(RING, I, ELTP) \
  _ring_get((void **)&RING, sizeof(RING[0]), (I), (ELTP))

/**
 * @brief Helper function used by ring_foreach().
 */
#define ring_enumerate_n(RING, I, ELTP, COUNT, BODY)                \
  ({                                                                \
    for ((I) = 0; (I) < MIN(ring_get_size(RING), (COUNT)); (I)++) { \
      ring_get((RING), (I), (ELTP));                                \
      { BODY; }                                                     \
    }                                                               \
  })

#define ring_enumerate(ring, i, eltp, BODY) \
  ring_enumerate_n((ring), (i), (eltp), 1, (BODY))

/**
 * @brief Iterate over elements in a ring.
 *
 * @param[in] pool The ring data structure to iterate over
 * @param[in, out] eltp A pointer to the element that will be used for
 * iteration
 * @param[in] BODY Block to execute during iteration
 *
 * @note Iteration will execute BODY with eltp corresponding successively to all
 * elements found in the ring. It is implemented using the more generic
 * enumeration function.
 */
#define ring_foreach_n(ring, eltp, count, BODY)                    \
  ({                                                               \
    unsigned _ring_var(i);                                         \
    ring_enumerate_n((ring), _ring_var(i), (eltp), (count), BODY); \
  })

#define ring_foreach(ring, eltp, BODY) ring_foreach_n((ring), (eltp), 1, (BODY))

#endif /* UTIL_RING_H */
