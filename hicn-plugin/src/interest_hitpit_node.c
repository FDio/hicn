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

#include <vnet/ip/ip6_packet.h>

#include "interest_hitpit.h"
#include "mgmt.h"
#include "parser.h"
#include "data_fwd.h"
#include "infra.h"
#include "strategy.h"
#include "strategy_dpo_ctx.h"
#include "strategy_dpo_manager.h"
#include "state.h"
#include "error.h"

/* packet trace format function */
static u8 *hicn_interest_hitpit_format_trace (u8 *s, va_list *args);

/* Stats string values */
static char *hicn_interest_hitpit_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

vlib_node_registration_t hicn_interest_hitpit_node;

/*
 * hICN forwarder node for interests hitting the PIT
 */
static uword
hicn_interest_hitpit_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  hicn_interest_hitpit_next_t next_index;
  hicn_interest_hitpit_runtime_t *rt;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  u32 n_left_to_next;
  vlib_buffer_t *b0;
  u32 bi0;
  u32 next0 = HICN_INTEREST_HITPIT_NEXT_ERROR_DROP;
  const hicn_strategy_vft_t *strategy_vft0;
  const hicn_dpo_vft_t *dpo_vft0;
  u8 dpo_ctx_id0;
  u8 forward = 0;
  u32 pit_entry_index;
  hicn_pcs_entry_t *pcs_entry = NULL;
  hicn_buffer_t *hicnb0;

  rt = vlib_node_get_runtime_data (vm, hicn_interest_hitpit_node.index);

  if (PREDICT_FALSE (rt->pitcs == NULL))
    {
      rt->pitcs = &hicn_main.pitcs;
    }
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  /* Prefetch for next iteration. */
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  /* Dequeue a packet buffer */
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Get hicn buffer and state */
	  hicnb0 = hicn_get_buffer (b0);
	  hicn_get_internal_state (hicnb0, &pit_entry_index, &strategy_vft0,
				   &dpo_vft0, &dpo_ctx_id0);

	  // Retrieve PIT entry
	  pcs_entry =
	    hicn_pcs_entry_get_entry_from_index (rt->pitcs, pit_entry_index);

	  // Increment packet counter
	  stats.pkts_processed += 1;

	  // A data packet may have arrived in the time between the pcs
	  // lookup and now. Check again to make sure the entry is CS or
	  // PIT
	  if (hicn_pcs_entry_is_cs (pcs_entry))
	    {
	      next0 = HICN_INTEREST_HITPIT_NEXT_INTEREST_HITCS;
	    }
	  else
	    {
	      // Distinguish between aggregation, retransmission and
	      // additionally check if the strategy mandates to always send
	      // the interest

	      // Retransmission
	      forward = hicn_pcs_entry_pit_search (pcs_entry, hicnb0->face_id);

	      // Strategy mandates to force send after aggregation
	      if (!forward && strategy_vft0->hicn_send_after_aggregation (
				dpo_ctx_id0, hicnb0->face_id))
		{
		  forward = true;
		  hicn_pcs_entry_pit_add_face (pcs_entry, hicnb0->face_id);
		}

	      if (forward && hicnb0->payload_type != HPT_MANIFEST)
		{
		  next0 = HICN_INTEREST_HITPIT_NEXT_STRATEGY;
		}
	      else
		{
		  // Aggregation
		  hicn_pcs_entry_pit_add_face (pcs_entry, hicnb0->face_id);

		  next0 = HICN_INTEREST_HITPIT_NEXT_ERROR_DROP;

		  stats.interests_aggregated++;
		}
	    }

	  /* Maybe trace */
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_interest_hitpit_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pkt_type = HICN_PACKET_TYPE_INTEREST;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	    }

	  /*
	   * Verify speculative enqueue, maybe switch current
	   * next frame
	   */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  u32 pit_int_count = hicn_pcs_get_pit_count (rt->pitcs);

  vlib_node_increment_counter (vm, hicn_interest_hitpit_node.index,
			       HICNFWD_ERROR_PROCESSED, stats.pkts_processed);
  vlib_node_increment_counter (vm, hicn_interest_hitpit_node.index,
			       HICNFWD_ERROR_INTEREST_AGG,
			       stats.interests_aggregated);
  vlib_node_increment_counter (vm, hicn_interest_hitpit_node.index,
			       HICNFWD_ERROR_INT_RETRANS,
			       stats.interests_retx);
  vlib_node_increment_counter (vm, hicn_interest_hitpit_node.index,
			       HICNFWD_ERROR_PIT_EXPIRED,
			       stats.pit_expired_count);
  vlib_node_increment_counter (vm, hicn_interest_hitpit_node.index,
			       HICNFWD_ERROR_HASH_COLL_HASHTB_COUNT,
			       stats.interests_hash_collision);

  update_node_counter (vm, hicn_interest_hitpit_node.index,
		       HICNFWD_ERROR_INT_COUNT, pit_int_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn_interest_hitpit_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_interest_hitpit_trace_t *t =
    va_arg (*args, hicn_interest_hitpit_trace_t *);

  s = format (s, "INTEREST-HITPIT: pkt: %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
VLIB_REGISTER_NODE(hicn_interest_hitpit_node) =
{
  .function = hicn_interest_hitpit_node_fn,
  .name = "hicn-interest-hitpit",
  .vector_size = sizeof(u32),
  .runtime_data_bytes = sizeof(hicn_interest_hitpit_runtime_t),
  .format_trace = hicn_interest_hitpit_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn_interest_hitpit_error_strings),
  .error_strings = hicn_interest_hitpit_error_strings,
  .n_next_nodes = HICN_INTEREST_HITPIT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN_INTEREST_HITPIT_NEXT_INTEREST_HITCS] = "hicn-interest-hitcs",
    [HICN_INTEREST_HITPIT_NEXT_STRATEGY] = "hicn-strategy",
    [HICN_INTEREST_HITPIT_NEXT_FACE4_OUTPUT] = "hicn4-face-output",
    [HICN_INTEREST_HITPIT_NEXT_FACE6_OUTPUT] = "hicn6-face-output",
    [HICN_INTEREST_HITPIT_NEXT_ERROR_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
