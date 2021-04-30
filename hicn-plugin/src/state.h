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

#ifndef __HICN_STATE__
#define __HICN_STATE__

#include <netinet/in.h>
#include <vnet/buffer.h>

#include "hicn.h"
#include "pcs.h"
#include "hashtb.h"
#include "strategy.h"
#include "strategy_dpo_ctx.h"
#include "strategy_dpo_manager.h"

/**
 * @file plugin_state
 *
 * Helper functions to hicn state (hash node, hash entry, strategy vft, dpo vft and dpo context id)
 *
 */

//TODO exploit this state to prefetch hash nodes and entries.

/**
 * @brief Retrieve the hicn state
 *
 * @param hicnb hicn buffer used to retrieve the hicn state
 * @param pitcs pointer to PIT/CS
 * @param node node in the hash table referring to the buffer
 * @param strategy_vft return value pointing to the strategy vft corresponding to the buffer
 * @param dpo_vft return value pointing to the dpo vft corresponding to the buffer
 * @param dpo_ctx_id return value pointing to the dpo context id corresponding to the buffer
 * @param hash_entry entry in the hash table referring to the buffer
 */
always_inline void
hicn_get_internal_state (hicn_buffer_t * hicnb, hicn_pit_cs_t * pitcs,
			 hicn_hash_node_t ** node,
			 const hicn_strategy_vft_t ** strategy_vft,
			 const hicn_dpo_vft_t ** dpo_vft, u8 * dpo_ctx_id,
			 hicn_hash_entry_t ** hash_entry)
{
  *node = pool_elt_at_index (pitcs->pcs_table->ht_nodes, hicnb->node_id);
  *strategy_vft = hicn_dpo_get_strategy_vft (hicnb->vft_id);
  *dpo_vft = hicn_dpo_get_vft (hicnb->vft_id);
  *dpo_ctx_id = hicnb->dpo_ctx_id;

  hicn_hash_bucket_t *bucket;
  if (hicnb->hash_bucket_flags & HICN_HASH_NODE_OVERFLOW_BUCKET)
    bucket =
      pool_elt_at_index (pitcs->pcs_table->ht_overflow_buckets,
			 hicnb->bucket_id);
  else
    bucket =
      (hicn_hash_bucket_t *) (pitcs->pcs_table->ht_buckets +
			      hicnb->bucket_id);

  *hash_entry = &(bucket->hb_entries[hicnb->hash_entry_id]);
}

/*
 * This function set the PCS entry index, the dpo index and the vft index in
 * the opaque2 buffer. In this way, the interest-hitpit and interest-hitcs
 * nodes can prefetch the corresponding state (PIT entry, dpo_ctx and the
 * strategy vft
 */
/**
 * @brief Store the hicn state in the hicn buffer
 *
 * @param b vlib buffer holding the hICN packet
 * @param name_hash hash of the hICN name
 * @param node_id id of the node in the hash table referring to the buffer
 * @param dpo_ctx_id id of the dpo context id corresponding to the buffer
 * @param vft_id id of the strategy vft corresponding to the buffer
 * @param hash_entry_id id of the entry in the hash table referring to the buffer
 * @param bucket_id id of the hasth table bucket that holds the hash entry
 * @param bucket_is_overflow 1 if the bucket is from the ht_overflow_buckets pool
 *                           0 if the bucket is from the ht_buckets pool
 */
always_inline void
hicn_store_internal_state (vlib_buffer_t * b, u64 name_hash, u32 node_id,
			   u8 dpo_ctx_id, u8 vft_id, u8 hash_entry_id,
			   u32 bucket_id, u8 bucket_is_overflow)
{
  hicn_buffer_t *hicnb = hicn_get_buffer (b);
  hicnb->name_hash = name_hash;
  hicnb->node_id = node_id;
  hicnb->dpo_ctx_id = dpo_ctx_id;
  hicnb->vft_id = vft_id;
  hicnb->hash_entry_id = hash_entry_id;
  hicnb->bucket_id = bucket_id;
  hicnb->hash_bucket_flags =
    HICN_HASH_NODE_OVERFLOW_BUCKET * bucket_is_overflow;
}

#endif /* // __HICN_STATE__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
