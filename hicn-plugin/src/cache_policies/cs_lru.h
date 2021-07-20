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

#ifndef __LRU_H__
#define __LRU_H__

#include "../pcs.h"
#include "../hashtb.h"
#include "cs_policy.h"

/**
 * @file cs_lru.h
 *
 * This file implements the LRU policy for the CS
 */

extern hicn_cs_policy_vft_t hicn_cs_lru;

/*
 * Insert a new CS element at the head of the CS LRU
 */
void hicn_cs_lru_insert (hicn_pit_cs_t *pcs, hicn_hash_node_t *pnode,
			 hicn_pcs_entry_t *entry, hicn_cs_policy_t *lru);

/*
 * Dequeue an LRU element, for example when it has expired.
 */
void hicn_cs_lru_dequeue (hicn_pit_cs_t *pcs, hicn_hash_node_t *pnode,
			  hicn_pcs_entry_t *entry, hicn_cs_policy_t *lru);

/*
 * Move a CS LRU element to the head, probably after it's been used.
 */
void hicn_cs_lru_update_head (hicn_pit_cs_t *pcs, hicn_hash_node_t *pnode,
			      hicn_pcs_entry_t *entry, hicn_cs_policy_t *lru);

void hicn_cs_lru_delete_get (hicn_pit_cs_t *p, hicn_cs_policy_t *policy,
			     hicn_hash_node_t **node, hicn_pcs_entry_t **pcs,
			     hicn_hash_entry_t **hash_entry);

/*
 * Remove a batch of nodes from the CS LRU, copying their node indexes into
 * the caller's array. We expect this is done when the LRU size exceeds the
 * CS's limit. Return the number of removed nodes.
 */
int hicn_cs_lru_trim (hicn_pit_cs_t *pcs, u32 *node_list, int sz,
		      hicn_cs_policy_t *lru);

int hicn_cs_lru_flush (vlib_main_t *vm, struct hicn_pit_cs_s *pitcs,
		       hicn_cs_policy_t *state);
#endif /* // __LRU_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
