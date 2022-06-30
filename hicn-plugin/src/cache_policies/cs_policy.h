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

#ifndef __HICN_CS_POLICY_H__
#define __HICN_CS_POLICY_H__

#include <vppinfra/types.h>
#include <vppinfra/clib.h>
#include <stddef.h>

/**
 * @file cs_policy.h
 *
 * This file provides the needed structures to implement a CS policy
 */

/* Forward declaration */
typedef struct hicn_pit_cs_s hicn_pit_cs_t;
typedef struct hicn_pcs_entry_s hicn_pcs_entry_t;
typedef struct hicn_cs_policy_s hicn_cs_policy_t;

/**
 * @brief Definition of the virtual functin table for a cache policy.
 *
 * A cache policy must implement all the following functions:
 * - insert: add a new element
 * - update: update the position of an existing element
 * - dequeue: remove an element from the list
 * - delete_get: return the next element that should be removed
 * - trim: trim last sz elements from the list
 * - flush: clean the cs
 */
typedef struct hicn_cs_policy_vft_s
{
  void (*hicn_cs_insert) (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
			  hicn_pcs_entry_t *pcs_entry);

  void (*hicn_cs_update) (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
			  hicn_pcs_entry_t *pcs_entry);

  void (*hicn_cs_dequeue) (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
			   hicn_pcs_entry_t *pcs_entry);

  void (*hicn_cs_delete_get) (hicn_cs_policy_t *policy,
			      const hicn_pit_cs_t *pcs,
			      hicn_pcs_entry_t **pcs_entry);

  int (*hicn_cs_trim) (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
		       u32 *node_list, size_t sz);

  int (*hicn_cs_flush) (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs);
} hicn_cs_policy_vft_t;

/*
 * CS policy
 */
typedef struct hicn_cs_policy_s
{
#define HICN_CS_POLICY_END_OF_CHAIN (u32) (~0)

  /*
   * VFT implementing the CS eviction/insertion policy. This must be the first
   * element of the structure.
   */
  hicn_cs_policy_vft_t vft;

  /*
   * Max number of element in CS
   */
  u32 max;

  /*
   * Number of element in CS
   */
  u32 count;

  /*
   * Head element of the CS (i.e. the most recent element used for LRU)
   */
  u32 head;

  /*
   * Tail element of the LRU (i.e. the next element to evict for LRU)
   */
  u32 tail;
} hicn_cs_policy_t;

/*
 * Get the max number of element in the CS
 */
always_inline u32
hicn_cs_policy_get_max (const hicn_cs_policy_t *policy)
{
  return policy->max;
}

/*
 * Get the number of element in the CS
 */
always_inline u32
hicn_cs_policy_get_count (const hicn_cs_policy_t *policy)
{
  return policy->count;
}

/*
 * Get the head element of the CS
 */
always_inline u32
hicn_cs_policy_get_head (const hicn_cs_policy_t *policy)
{
  return policy->head;
}

/*
 * Get the tail element of the CS
 */
always_inline u32
hicn_cs_policy_get_tail (const hicn_cs_policy_t *policy)
{
  return policy->tail;
}

always_inline void
hicn_cs_policy_insert (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
		       hicn_pcs_entry_t *pcs_entry)
{
  return policy->vft.hicn_cs_insert (policy, pcs, pcs_entry);
}

always_inline void
hicn_cs_policy_update (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
		       hicn_pcs_entry_t *pcs_entry)
{
  return policy->vft.hicn_cs_update (policy, pcs, pcs_entry);
}

always_inline void
hicn_cs_policy_dequeue (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
			hicn_pcs_entry_t *pcs_entry)
{
  return policy->vft.hicn_cs_dequeue (policy, pcs, pcs_entry);
}

always_inline void
hicn_cs_policy_delete_get (hicn_cs_policy_t *policy, const hicn_pit_cs_t *pcs,
			   hicn_pcs_entry_t **pcs_entry)
{
  return policy->vft.hicn_cs_delete_get (policy, pcs, pcs_entry);
}

always_inline int
hicn_cs_policy_trim (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
		     u32 *node_list, int sz)
{
  return policy->vft.hicn_cs_trim (policy, pcs, node_list, sz);
}

always_inline int
hicn_cs_policy_flush (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs)
{
  return policy->vft.hicn_cs_flush (policy, pcs);
}

#endif /* __HICN_POLICY_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
