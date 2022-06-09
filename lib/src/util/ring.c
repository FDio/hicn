
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
 * \file ring.c
 * \brief Implementation of ring buffer.
 */

#include <stdlib.h>

#include <hicn/util/ring.h>

void
_ring_init (void **ring_ptr, size_t elt_size, size_t max_size)
{
  assert (ring_ptr);
  assert (elt_size > 0);
  // we use a static array, not a vector (for now)
  assert (max_size != 0);

  ring_hdr_t *rh = malloc (RING_HDRLEN + max_size * elt_size);

  rh->roff = 0;
  rh->woff = 0;
  rh->size = 0;
  rh->max_size = max_size;

  *ring_ptr = (uint8_t *) rh + RING_HDRLEN;
}

void
_ring_free (void **ring_ptr)
{
  free (ring_hdr (*ring_ptr));
  *ring_ptr = NULL;
}
