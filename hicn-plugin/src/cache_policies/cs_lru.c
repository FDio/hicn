/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#include "../hashtb.h"
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
};

/*
 * Insert a new CS element at the head of the CS LRU
 */
void
hicn_cs_lru_insert (hicn_pit_cs_t * p, hicn_hash_node_t * node,
		    hicn_pcs_entry_t * pcs, hicn_cs_policy_t * policy_state)
{
  hicn_hash_node_t *lrunode;
  hicn_pcs_entry_t *lrupcs;
  u32 idx;

  idx = hicn_hashtb_node_idx_from_node (p->pcs_table, node);

  if (policy_state->head != 0)
    {
      lrunode = hicn_hashtb_node_from_idx (p->pcs_table, policy_state->head);
      lrupcs = hicn_pit_get_data (lrunode);

      ASSERT (lrupcs->u.cs.cs_lru_prev == 0);
      lrupcs->u.cs.cs_lru_prev = idx;

      pcs->u.cs.cs_lru_prev = 0;
      pcs->u.cs.cs_lru_next = policy_state->head;

      policy_state->head = idx;
    }
  else
    {
      ASSERT (policy_state->tail == 0);	/* We think the list is
					 * empty */

      policy_state->head = policy_state->tail = idx;

      pcs->u.cs.cs_lru_next = pcs->u.cs.cs_lru_prev = 0;
    }

  policy_state->count++;
}

void
hicn_cs_lru_delete_get (hicn_pit_cs_t * p, hicn_cs_policy_t * policy_state,
			hicn_hash_node_t ** nodep,
			hicn_pcs_entry_t ** pcs_entry,
			hicn_hash_entry_t ** hash_entry)
{
  *nodep = hicn_hashtb_node_from_idx (p->pcs_table, policy_state->tail);
  *pcs_entry = hicn_pit_get_data (*nodep);

  *hash_entry = hicn_hashtb_get_entry (p->pcs_table, (*nodep)->entry_idx,
				       (*nodep)->bucket_id,
				       (*nodep)->hn_flags &
				       HICN_HASH_NODE_OVERFLOW_BUCKET);
}

/*
 * Dequeue an LRU element, for example when it has expired.
 */
void
hicn_cs_lru_dequeue (hicn_pit_cs_t * pit, hicn_hash_node_t * pnode,
		     hicn_pcs_entry_t * pcs, hicn_cs_policy_t * lru)
{
  hicn_hash_node_t *lrunode;
  hicn_pcs_entry_t *lrupcs;

  if (pcs->u.cs.cs_lru_prev != 0)
    {
      /* Not already on the head of the LRU */
      lrunode = hicn_hashtb_node_from_idx (pit->pcs_table,
					   pcs->u.cs.cs_lru_prev);
      lrupcs = hicn_pit_get_data (lrunode);

      lrupcs->u.cs.cs_lru_next = pcs->u.cs.cs_lru_next;
    }
  else
    {
      ASSERT (lru->head ==
	      hicn_hashtb_node_idx_from_node (pit->pcs_table, pnode));
      lru->head = pcs->u.cs.cs_lru_next;
    }

  if (pcs->u.cs.cs_lru_next != 0)
    {
      /* Not already the end of the LRU */
      lrunode = hicn_hashtb_node_from_idx (pit->pcs_table,
					   pcs->u.cs.cs_lru_next);
      lrupcs = hicn_pit_get_data (lrunode);

      lrupcs->u.cs.cs_lru_prev = pcs->u.cs.cs_lru_prev;
    }
  else
    {
      /* This was the last LRU element */
      ASSERT (lru->tail ==
	      hicn_hashtb_node_idx_from_node (pit->pcs_table, pnode));
      lru->tail = pcs->u.cs.cs_lru_prev;
    }

  pcs->u.cs.cs_lru_next = pcs->u.cs.cs_lru_prev = 0;
  lru->count--;
}

/*
 * Move a CS LRU element to the head, probably after it's been used.
 */
void
hicn_cs_lru_update_head (hicn_pit_cs_t * pit, hicn_hash_node_t * pnode,
			 hicn_pcs_entry_t * pcs, hicn_cs_policy_t * lru)
{
  if (pcs->u.cs.cs_lru_prev != 0)
    {
      /*
       * Not already on the head of the LRU, detach it from its
       * current position
       */
      hicn_cs_lru_dequeue (pit, pnode, pcs, lru);

      /* Now detached from the list; attach at head */
      hicn_cs_lru_insert (pit, pnode, pcs, lru);

    }
  else
    {
      ASSERT (lru->head ==
	      hicn_hashtb_node_idx_from_node (pit->pcs_table, pnode));
    }
}

/*
 * Remove a batch of nodes from the CS LRU, copying their node indexes into
 * the caller's array. We expect this is done when the LRU size exceeds the
 * CS's limit. Return the number of removed nodes.
 */
int
hicn_cs_lru_trim (hicn_pit_cs_t * pit, u32 * node_list, int sz,
		  hicn_cs_policy_t * lru)
{
  hicn_hash_node_t *lrunode;
  hicn_pcs_entry_t *lrupcs;
  u32 idx;
  int i;

  idx = lru->tail;

  for (i = 0; i < sz; i++)
    {

      if (idx == 0)
	{
	  break;
	}
      lrunode = hicn_hashtb_node_from_idx (pit->pcs_table, idx);
      lrupcs = hicn_pit_get_data (lrunode);

      node_list[i] = idx;

      idx = lrupcs->u.cs.cs_lru_prev;
      lrupcs->u.cs.cs_lru_prev = 0;
      lrupcs->u.cs.cs_lru_next = 0;
    }

  lru->count -= i;

  lru->tail = idx;
  if (idx != 0)
    {
      lrunode = hicn_hashtb_node_from_idx (pit->pcs_table, idx);
      lrupcs = hicn_pit_get_data (lrunode);

      lrupcs->u.cs.cs_lru_next = 0;
    }
  else
    {
      /* If the tail is empty, the whole lru is empty */
      lru->head = 0;
    }

  return (i);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
