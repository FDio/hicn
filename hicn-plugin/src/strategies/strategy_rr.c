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

#include "dpo_rr.h"
#include "../strategy.h"
#include "../strategy_dpo_ctx.h"
#include "../faces/face.h"
#include "../hashtb.h"
#include "../strategy_dpo_manager.h"

/* Simple strategy that chooses the next hop with the maximum weight */
/* It does not require to exend the hicn_dpo */
void hicn_receive_data_rr (index_t dpo_idx, int nh_idx);
void hicn_add_interest_rr (index_t dpo_idx, hicn_hash_entry_t * pit_entry);
void hicn_on_interest_timeout_rr (index_t dpo_idx);
u32 hicn_select_next_hop_rr (index_t dpo_idx, int *nh_idx,
			     dpo_id_t ** outface);
u8 * hicn_strategy_format_trace_rr (u8 * s, hicn_strategy_trace_t * t);
u8 * hicn_strategy_format_rr (u8 * s, va_list * ap);


static hicn_strategy_vft_t hicn_strategy_rr_vft = {
  .hicn_receive_data = &hicn_receive_data_rr,
  .hicn_add_interest = &hicn_add_interest_rr,
  .hicn_on_interest_timeout = &hicn_on_interest_timeout_rr,
  .hicn_select_next_hop = &hicn_select_next_hop_rr,
  .hicn_format_strategy_trace = &hicn_strategy_format_trace_rr,
  .hicn_format_strategy = &hicn_strategy_format_rr
};

/*
 * Return the vft of the strategy.
 */
hicn_strategy_vft_t *
hicn_rr_strategy_get_vft (void)
{
  return &hicn_strategy_rr_vft;
}

/* DPO should be give in input as it containes all the information to calculate the next hops*/
u32
hicn_select_next_hop_rr (index_t dpo_idx, int *nh_idx, dpo_id_t ** outface)
{
  hicn_dpo_ctx_t * dpo_ctx = hicn_strategy_dpo_ctx_get (dpo_idx);

  if(dpo_ctx == NULL)
    return HICN_ERROR_STRATEGY_NOT_FOUND;

  hicn_strategy_rr_ctx_t *hicn_strategy_rr_ctx =
    (hicn_strategy_rr_ctx_t *) dpo_ctx->data;

  if (dpo_id_is_valid
      (&dpo_ctx->next_hops[hicn_strategy_rr_ctx->current_nhop]))
    {
      *outface =
	(dpo_id_t *) & dpo_ctx->next_hops[hicn_strategy_rr_ctx->current_nhop];

    }
  else
    return HICN_ERROR_STRATEGY_NH_NOT_FOUND;

  hicn_strategy_rr_ctx->current_nhop =
    (hicn_strategy_rr_ctx->current_nhop +
     1) % dpo_ctx->entry_count;

  return HICN_ERROR_NONE;
}

void
hicn_add_interest_rr (index_t dpo_ctx_idx, hicn_hash_entry_t * hash_entry)
{
  hash_entry->dpo_ctx_id = dpo_ctx_idx;
  dpo_id_t hicn_dpo_id =
    { hicn_dpo_strategy_rr_get_type (), 0, 0, dpo_ctx_idx };
  hicn_strategy_dpo_ctx_lock (&hicn_dpo_id);
  hash_entry->vft_id = hicn_dpo_get_vft_id (&hicn_dpo_id);
}

void
hicn_on_interest_timeout_rr (index_t dpo_idx)
{
  /* Nothing to do in the rr strategy when we receive an interest */
}

void
hicn_receive_data_rr (index_t dpo_idx, int nh_idx)
{
}


/* packet trace format function */
u8 *
hicn_strategy_format_trace_rr (u8 * s, hicn_strategy_trace_t * t)
{
  s = format (s, "Strategy_rr: pkt: %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);
  return (s);
}

u8 *
hicn_strategy_format_rr (u8 * s, va_list * ap)
{

  u32 indent = va_arg (*ap, u32);
  s =
    format (s,
	    "Round Robin: next hop is chosen ciclying between all the available next hops, one after the other.\n",
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
