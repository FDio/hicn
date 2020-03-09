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

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "../strategy.h"
#include "../strategy_dpo_ctx.h"
#include "dpo_rr.h"
#include "../faces/face.h"
#include "../route.h"
#include "../pcs.h"
#include "../strategy_dpo_manager.h"

/* Simple strategy that chooses the next hop with the maximum weight */
/* It does not require to exend the hicn_dpo */
void hicn_receive_data_rr (index_t dpo_idx, int nh_idx);
void hicn_add_interest_rr (index_t dpo_idx, hicn_hash_entry_t * pit_entry);
void hicn_on_interest_timeout_rr (index_t dpo_idx);
u32 hicn_select_next_hop_rr (index_t dpo_idx, int *nh_idx,
			     dpo_id_t ** outface);
u8 * hicn_strategy_format_trace_rr (u8 * s, hicn_strategy_trace_t * t);


static hicn_strategy_vft_t hicn_strategy_rr_vft = {
  .hicn_receive_data = &hicn_receive_data_rr,
  .hicn_add_interest = &hicn_add_interest_rr,
  .hicn_on_interest_timeout = &hicn_on_interest_timeout_rr,
  .hicn_select_next_hop = &hicn_select_next_hop_rr,
  .hicn_format_strategy = hicn_strategy_format_trace_rr
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
  hicn_strategy_rr_ctx_t *hicn_strategy_rr_ctx =
    (hicn_strategy_rr_ctx_t *) hicn_strategy_rr_ctx_get (dpo_idx);

  if (dpo_id_is_valid
      (&hicn_strategy_rr_ctx->default_ctx.
       next_hops[hicn_strategy_rr_ctx->current_nhop]))
    {
      *outface =
	(dpo_id_t *) & hicn_strategy_rr_ctx->default_ctx.
	next_hops[hicn_strategy_rr_ctx->current_nhop];

    }
  else
    return HICN_ERROR_STRATEGY_NH_NOT_FOUND;

  hicn_strategy_rr_ctx->current_nhop =
    (hicn_strategy_rr_ctx->current_nhop +
     1) % hicn_strategy_rr_ctx->default_ctx.entry_count;

  return HICN_ERROR_NONE;
}

/* uword */
/* hicn_rr_strategy_node_fn (vlib_main_t * vm, */
/* 			  vlib_node_runtime_t * node, vlib_frame_t * frame) */
/* { */
/*   return hicn_forward_interest_fn (vm, node, frame, &hicn_strategy_rr_vft, */
/* 				   hicn_dpo_strategy_rr_get_type (), */
/* 				   &hicn_rr_strategy_node); */
/* } */

void
hicn_add_interest_rr (index_t dpo_ctx_idx, hicn_hash_entry_t * hash_entry)
{
  hash_entry->dpo_ctx_id = dpo_ctx_idx;
  dpo_id_t hicn_dpo_id =
    { hicn_dpo_strategy_rr_get_type (), 0, 0, dpo_ctx_idx };
  hicn_strategy_rr_ctx_lock (&hicn_dpo_id);
  hash_entry->vft_id = hicn_dpo_get_vft_id (&hicn_dpo_id);
}

void
hicn_on_interest_timeout_rr (index_t dpo_idx)
{
  /* Nothign to do in the rr strategy when we receive an interest */
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

/* /\* */
/*  * Node registration for the forwarder node */
/*  *\/ */
/* /\* *INDENT-OFF* *\/ */
/* VLIB_REGISTER_NODE (hicn_rr_strategy_node) = */
/* { */
/*   .name = "hicn-rr-strategy", */
/*   .function = hicn_rr_strategy_node_fn, */
/*   .vector_size = sizeof (u32), */
/*   .runtime_data_bytes = sizeof (int) + sizeof(hicn_pit_cs_t *), */
/*   .format_trace = hicn_strategy_format_trace_rr, */
/*   .type = VLIB_NODE_TYPE_INTERNAL, */
/*   .n_errors = ARRAY_LEN (hicn_strategy_error_strings), */
/*   .error_strings = hicn_strategy_error_strings, */
/*   .n_next_nodes = HICN_STRATEGY_N_NEXT, */
/*   .next_nodes = { */
/*     [HICN_STRATEGY_NEXT_INTEREST_HITPIT] = "hicn-interest-hitpit", */
/*     [HICN_STRATEGY_NEXT_INTEREST_HITCS] = "hicn-interest-hitcs", */
/*     [HICN_STRATEGY_NEXT_ERROR_DROP] = "error-drop", */
/*     [HICN_STRATEGY_NEXT_EMPTY] = "ip4-lookup", */
/*   }, */
/* }; */
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
