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

#ifndef __LRU_H__
#define __LRU_H__

#include "../pcs.h"
#include "cs_policy.h"

/**
 * @file cs_lru.h
 *
 * This file implements the LRU policy for the CS
 */

extern hicn_cs_policy_vft_t hicn_cs_lru;

/**
 * @brief Insert a new CS element at the head of the CS LRU
 *
 * @param policy the cs insertion/eviction policy - LRU
 * @param pcs the PCS table
 * @param pcs_entry the PCS entry to insert
 * @return 0 on success, -1 on overflow
 */
void hicn_cs_lru_insert (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
			 hicn_pcs_entry_t *pcs_entry);

/*
 * Dequeue an LRU element, for example when it has expired.
 */
void hicn_cs_lru_dequeue (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
			  hicn_pcs_entry_t *pcs_entry);

/*
 * Move a CS LRU element to the head, probably after it's been used.
 */
void hicn_cs_lru_update_head (hicn_cs_policy_t *lru, hicn_pit_cs_t *pcs,
			      hicn_pcs_entry_t *entry);

void hicn_cs_lru_delete_get (hicn_cs_policy_t *policy,
			     const hicn_pit_cs_t *pcs,
			     hicn_pcs_entry_t **pcs_entry);

/*
 * Remove a batch of nodes from the CS LRU, copying their node indexes into
 * the caller's array. We expect this is done when the LRU size exceeds the
 * CS's limit. Return the number of removed nodes.
 */
int hicn_cs_lru_trim (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs,
		      u32 *node_list, size_t sz);

int hicn_cs_lru_flush (hicn_cs_policy_t *policy, hicn_pit_cs_t *pcs);

hicn_cs_policy_t hicn_cs_lru_create (u32 max_elts);

#endif /* __LRU_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
