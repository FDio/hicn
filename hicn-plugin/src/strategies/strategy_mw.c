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

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "../strategy.h"
#include "../strategy_dpo_ctx.h"
#include "dpo_mw.h"
#include "../faces/face.h"
//#include "../route.h"
//#include "../pcs.h"
#include "../hashtb.h"
#include "../strategy_dpo_manager.h"

/* Simple strategy that chooses the next hop with the maximum weight */
/* It does not require to exend the hicn_dpo */
void hicn_receive_data_mw (index_t dpo_idx, int nh_idx);
void hicn_add_interest_mw (index_t dpo_idx, hicn_hash_entry_t * pit_entry);
void hicn_on_interest_timeout_mw (index_t dpo_idx);
u32 hicn_select_next_hop_mw (index_t dpo_idx, int *nh_idx,
			     dpo_id_t ** outface);
u32 get_strategy_node_index_mw (void);
u8 * hicn_strategy_format_trace_mw (u8 * s, hicn_strategy_trace_t * t);
u8 * hicn_strategy_format_mw (u8 * s, va_list * ap);


static hicn_strategy_vft_t hicn_strategy_mw_vft = {
  .hicn_receive_data = &hicn_receive_data_mw,
  .hicn_add_interest = &hicn_add_interest_mw,
  .hicn_on_interest_timeout = &hicn_on_interest_timeout_mw,
  .hicn_select_next_hop = &hicn_select_next_hop_mw,
  .hicn_format_strategy_trace = hicn_strategy_format_trace_mw,
  .hicn_format_strategy = &hicn_strategy_format_mw
};

/*
 * Return the vft of the strategy.
 */
hicn_strategy_vft_t *
hicn_mw_strategy_get_vft (void)
{
  return &hicn_strategy_mw_vft;
}

/* DPO should be give in input as it containes all the information to calculate the next hops*/
u32
hicn_select_next_hop_mw (index_t dpo_idx, int *nh_idx, dpo_id_t ** outface)
{
  hicn_dpo_ctx_t * dpo_ctx = hicn_strategy_dpo_ctx_get (dpo_idx);

  if(dpo_ctx == NULL)
    return HICN_ERROR_STRATEGY_NOT_FOUND;

  hicn_strategy_mw_ctx_t *hicn_strategy_mw_ctx =
    (hicn_strategy_mw_ctx_t *) dpo_ctx->data;

  u8 next_hop_index = 0;
  for (int i = 0; i < dpo_ctx->entry_count; i++)
    {
      if (dpo_id_is_valid (&dpo_ctx->next_hops[i]))
	{
	  if (hicn_strategy_mw_ctx->weight[next_hop_index] <
	      hicn_strategy_mw_ctx->weight[i])
	    {
	      next_hop_index = i;
	    }
	}
    }

  if (!dpo_id_is_valid
      (&dpo_ctx->next_hops[next_hop_index]))
    return HICN_ERROR_STRATEGY_NH_NOT_FOUND;

  *outface =
    (dpo_id_t *) & dpo_ctx->next_hops[next_hop_index];

  return HICN_ERROR_NONE;
}

void
hicn_add_interest_mw (index_t dpo_ctx_idx, hicn_hash_entry_t * hash_entry)
{
  hash_entry->dpo_ctx_id = dpo_ctx_idx;
  dpo_id_t hicn_dpo_id =
    { hicn_dpo_strategy_mw_get_type (), 0, 0, dpo_ctx_idx };
  hicn_strategy_dpo_ctx_lock (&hicn_dpo_id);
  hash_entry->vft_id = hicn_dpo_get_vft_id (&hicn_dpo_id);
}

void
hicn_on_interest_timeout_mw (index_t dpo_idx)
{
  /* Nothign to do in the mw strategy when we receive an interest */
}

void
hicn_receive_data_mw (index_t dpo_idx, int nh_idx)
{
}


/* packet trace format function */
u8 *
hicn_strategy_format_trace_mw (u8 * s, hicn_strategy_trace_t * t)
{
  s = format (s, "Strategy_mw: pkt: %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);
  return (s);
}

u8 *
hicn_strategy_format_mw (u8 * s, va_list * ap)
{

  u32 indent = va_arg (*ap, u32);
  s =
    format (s,
	    "Static Weights: weights are updated by the control plane, next hop is the one with the maximum weight.\n",
	    indent);
  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
