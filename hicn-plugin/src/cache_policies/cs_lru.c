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

#include "../strategy_dpo_manager.h"
#include "../error.h"
#include "cs_lru.h"
#include "cs_policy.h"

hicn_cs_policy_vft_t hicn_cs_lru = {
  .hicn_cs_insert = &hicn_cs_lru_insert,
  .hicn_cs_update = &hicn_cs_lru_update_head,
  .hicn_cs_dequeue = &hicn_cs_lru_dequeue,
  .hicn_cs_delete_get = &hicn_cs_lru_delete_get,
  .hicn_cs_trim = &hicn_cs_lru_trim,
  .hicn_cs_flush = &hicn_cs_lru_flush,
};

/*
 * Insert a new CS element at the head of the CS LRU
 */
void
hicn_cs_lru_insert (hicn_cs_policy_t *lru_policy, hicn_pit_cs_t *pcs,
		    hicn_pcs_entry_t *pcs_entry)
{
  hicn_pcs_entry_t *lrupcs;
  u32 idx;

  idx = hicn_pcs_entry_get_index (pcs, pcs_entry);

  if (lru_policy->head != HICN_CS_POLICY_END_OF_CHAIN)
    {
      lrupcs = hicn_pcs_entry_get_entry_from_index (pcs, lru_policy->head);

      ASSERT (lrupcs->u.cs.cs_lru_prev == HICN_CS_POLICY_END_OF_CHAIN);
      lrupcs->u.cs.cs_lru_prev = idx;

      pcs_entry->u.cs.cs_lru_prev = HICN_CS_POLICY_END_OF_CHAIN;
      pcs_entry->u.cs.cs_lru_next = lru_policy->head;

      lru_policy->head = idx;
    }
  else
    {
      // The list should be empty
      ASSERT (lru_policy->tail == HICN_CS_POLICY_END_OF_CHAIN);

      lru_policy->head = lru_policy->tail = idx;

      pcs_entry->u.cs.cs_lru_next = pcs_entry->u.cs.cs_lru_prev =
	HICN_CS_POLICY_END_OF_CHAIN;
    }

  lru_policy->count++;
}

void
hicn_cs_lru_delete_get (hicn_cs_policy_t *lru_policy, const hicn_pit_cs_t *pcs,
			hicn_pcs_entry_t **pcs_entry)
{
  *pcs_entry = hicn_pcs_entry_get_entry_from_index (pcs, lru_policy->tail);
}

/*
 * Dequeue an LRU element, for example when it has expired.
 */
void
hicn_cs_lru_dequeue (hicn_cs_policy_t *lru_policy, hicn_pit_cs_t *pcs,
		     hicn_pcs_entry_t *pcs_entry)
{
  hicn_pcs_entry_t *lrupcs;

  if (pcs_entry->u.cs.cs_lru_prev != HICN_CS_POLICY_END_OF_CHAIN)
    {
      /* Not already on the head of the LRU */
      lrupcs =
	hicn_pcs_entry_get_entry_from_index (pcs, pcs_entry->u.cs.cs_lru_prev);

      lrupcs->u.cs.cs_lru_next = pcs_entry->u.cs.cs_lru_next;
    }
  else
    {
      ASSERT (lru_policy->head == hicn_pcs_entry_get_index (pcs, pcs_entry));
      lru_policy->head = pcs_entry->u.cs.cs_lru_next;
    }

  if (pcs_entry->u.cs.cs_lru_next != HICN_CS_POLICY_END_OF_CHAIN)
    {
      /* Not already the end of the LRU */
      lrupcs =
	hicn_pcs_entry_get_entry_from_index (pcs, pcs_entry->u.cs.cs_lru_next);

      lrupcs->u.cs.cs_lru_prev = pcs_entry->u.cs.cs_lru_prev;
    }
  else
    {
      /* This was the last LRU element */
      ASSERT (lru_policy->tail == hicn_pcs_entry_get_index (pcs, pcs_entry));
      lru_policy->tail = pcs_entry->u.cs.cs_lru_prev;
    }

  pcs_entry->u.cs.cs_lru_next = pcs_entry->u.cs.cs_lru_prev =
    HICN_CS_POLICY_END_OF_CHAIN;
  lru_policy->count--;
}

/*
 * Move a CS LRU element to the head. The element must be part of the LRU list.
 */
void
hicn_cs_lru_update_head (hicn_cs_policy_t *lru_policy, hicn_pit_cs_t *pcs,
			 hicn_pcs_entry_t *pcs_entry)
{
  if (pcs_entry->u.cs.cs_lru_prev != HICN_CS_POLICY_END_OF_CHAIN)
    {
      /*
       * Not already on the head of the LRU, detach it from its
       * current position
       */
      hicn_cs_lru_dequeue (lru_policy, pcs, pcs_entry);

      /* Now detached from the list; attach at head */
      hicn_cs_lru_insert (lru_policy, pcs, pcs_entry);
    }
  else
    {
      // The element must be already at the head of the LRU
      ASSERT (lru_policy->head == hicn_pcs_entry_get_index (pcs, pcs_entry));
    }
}

/*
 * Remove a batch of nodes from the CS LRU, copying their node indexes into
 * the caller's array. We expect this is done when the LRU size exceeds the
 * CS's limit. Return the number of removed nodes.
 */
int
hicn_cs_lru_trim (hicn_cs_policy_t *lru_policy, hicn_pit_cs_t *pcs,
		  u32 *node_list, size_t sz)
{
  hicn_pcs_entry_t *lrupcs;
  u32 idx;
  int i;

  idx = lru_policy->tail;

  for (i = 0; i < sz && idx > 0; i++)
    {
      lrupcs = hicn_pcs_entry_get_entry_from_index (pcs, idx);

      node_list[i] = idx;

      idx = lrupcs->u.cs.cs_lru_prev;
      lrupcs->u.cs.cs_lru_prev = HICN_CS_POLICY_END_OF_CHAIN;
      lrupcs->u.cs.cs_lru_next = HICN_CS_POLICY_END_OF_CHAIN;
    }

  lru_policy->count -= i;
  lru_policy->tail = idx;

  if (idx != HICN_CS_POLICY_END_OF_CHAIN)
    {
      lrupcs = hicn_pcs_entry_get_entry_from_index (pcs, idx);
      lrupcs->u.cs.cs_lru_next = HICN_CS_POLICY_END_OF_CHAIN;
    }
  else
    {
      /* If the tail is empty, the whole lru is empty */
      lru_policy->head = HICN_CS_POLICY_END_OF_CHAIN;
    }

  return i;
}

int
hicn_cs_lru_flush (hicn_cs_policy_t *lru_policy, hicn_pit_cs_t *pcs)
{
  if (lru_policy->head == HICN_CS_POLICY_END_OF_CHAIN &&
      lru_policy->tail == HICN_CS_POLICY_END_OF_CHAIN)
    return 0;

  hicn_pcs_entry_t *pcs_entry;
  u32 idx;
  int i = 0;

  idx = lru_policy->tail;

  while (idx != HICN_CS_POLICY_END_OF_CHAIN)
    {
      // Get tail entry
      pcs_entry = hicn_pcs_entry_get_entry_from_index (pcs, idx);

      // Delete entry from the PCS. This will also update the LRU.
      hicn_pcs_entry_remove_lock (pcs, pcs_entry);

      // Set index to the new tail (updated in the previous call)
      idx = lru_policy->tail;

      // Advance counter
      i++;
    }

  return i;
}

hicn_cs_policy_t
hicn_cs_lru_create (u32 max_elts)
{
  hicn_cs_policy_t policy = {
    .vft = hicn_cs_lru,
    .head = HICN_CS_POLICY_END_OF_CHAIN,
    .tail = HICN_CS_POLICY_END_OF_CHAIN,
    .count = 0,
    .max = max_elts,
  };

  return policy;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
