/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#include "../hashtb.h"

/**
 * @file cs_policy.h
 *
 * This file provides the needed structures to implement a CS policy
 */


/*
 * Structure
 */
typedef struct hicn_cs_policy_s
{
  u32 max;
  u32 count;

  /* Indexes to hashtable nodes forming CS LRU */
  u32 head;
  u32 tail;

} hicn_cs_policy_t;

/* Forward declaration */
struct hicn_pit_cs_s;
struct hicn_hash_node_s;
struct hicn_pcs_entry_s;
struct hicn_cs_policy_s;

/**
 * @brief Definition of the virtual functin table for a cache policy.
 *
 * A cache policy must implement all the following functions:
 * - insert: add a new element
 * - update: update the position of an existing element
 * - dequeue: remove an element from the list
 * - delete_get: return the next element that should be removed trim
 * - flush: clean the cs
 */
typedef struct hicn_cs_policy_vft_s
{
  void (*hicn_cs_insert) (struct hicn_pit_cs_s * p,
			  struct hicn_hash_node_s * node,
			  struct hicn_pcs_entry_s * pcs,
			  hicn_cs_policy_t * policy);

  void (*hicn_cs_update) (struct hicn_pit_cs_s * p,
			  struct hicn_hash_node_s * node,
			  struct hicn_pcs_entry_s * pcs,
			  hicn_cs_policy_t * policy);

  void (*hicn_cs_dequeue) (struct hicn_pit_cs_s * p,
			   struct hicn_hash_node_s * node,
			   struct hicn_pcs_entry_s * pcs,
			   hicn_cs_policy_t * policy);

  void (*hicn_cs_delete_get) (struct hicn_pit_cs_s * p,
			      hicn_cs_policy_t * policy,
			      struct hicn_hash_node_s ** node,
			      struct hicn_pcs_entry_s ** pcs,
			      struct hicn_hash_entry_s ** hash_entry);

  int (*hicn_cs_trim) (struct hicn_pit_cs_s * p, u32 * node_list, int sz,
		       hicn_cs_policy_t * policy);

  int (*hicn_cs_flush) (vlib_main_t * vm, struct hicn_pit_cs_s * p,
			hicn_cs_policy_t * policy_state);
} hicn_cs_policy_vft_t;



#endif /* // __HICN_POLICY_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
