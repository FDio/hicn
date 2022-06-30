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

#ifndef __HICN_STATE__
#define __HICN_STATE__

#include <netinet/in.h>
#include <vnet/buffer.h>

#include "hicn.h"
#include "pcs.h"
#include "strategy.h"
#include "strategy_dpo_ctx.h"
#include "strategy_dpo_manager.h"

/**
 * @file plugin_state
 *
 * Helper functions to hicn state (hash node, hash entry, strategy vft, dpo vft
 * and dpo context id)
 *
 */

// TODO exploit this state to prefetch hash nodes and entries.

/**
 * @brief Retrieve the hicn state
 *
 * @param hicnb hicn buffer used to retrieve the hicn state
 * @param pitcs pointer to PIT/CS
 * @param node node in the hash table referring to the buffer
 * @param strategy_vft return value pointing to the strategy vft corresponding
 * to the buffer
 * @param dpo_vft return value pointing to the dpo vft corresponding to the
 * buffer
 * @param dpo_ctx_id return value pointing to the dpo context id corresponding
 * to the buffer
 * @param hash_entry entry in the hash table referring to the buffer
 */
always_inline void
hicn_get_internal_state (hicn_buffer_t *hicnb, u32 *pit_entry_index,
			 const hicn_strategy_vft_t **strategy_vft,
			 const hicn_dpo_vft_t **dpo_vft, u8 *dpo_ctx_id)
{
  *pit_entry_index = hicnb->pcs_entry_id;
  *strategy_vft = hicn_dpo_get_strategy_vft (hicnb->vft_id);
  *dpo_vft = hicn_dpo_get_vft (hicnb->vft_id);
  *dpo_ctx_id = hicnb->dpo_ctx_id;
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
 * @param pcs_entry_index index of the PCS entry
 */
always_inline int
hicn_store_internal_state (vlib_buffer_t *b, u32 pcs_entry_index,
			   u32 dpo_ctx_id)
{
  hicn_buffer_t *hicnb = hicn_get_buffer (b);

  hicnb->dpo_ctx_id = dpo_ctx_id;
  const hicn_dpo_ctx_t *dpo_ctx =
    hicn_strategy_dpo_ctx_get (hicnb->dpo_ctx_id);

  if (PREDICT_FALSE (dpo_ctx == NULL))
    return HICN_ERROR_DPO_CTX_NOT_FOUND;

  hicnb->vft_id = dpo_ctx->dpo_type;
  hicnb->pcs_entry_id = pcs_entry_index;

  return HICN_ERROR_NONE;
}

#endif /* // __HICN_STATE__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
