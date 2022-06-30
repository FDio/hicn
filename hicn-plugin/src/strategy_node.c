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

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "hicn.h"
#include "parser.h"
#include "strategy.h"
#include "strategy_dpo_ctx.h"
#include "infra.h"
#include "mgmt.h"
#include "pcs.h"
#include "state.h"
#include "data_fwd.h"
#include "strategies/strategy_mw.h"

/* Registration struct for a graph node */
vlib_node_registration_t hicn_strategy_node;

/*
 * Node context data (to be used in all the strategy nodes); we think this is
 * per-thread/instance
 */
typedef struct hicn_strategy_runtime_s
{
  int id;
  hicn_pit_cs_t *pitcs;
} hicn_strategy_runtime_t;

/* Stats string values */
static char *hicn_strategy_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

/* packet trace format function */
u8 *
hicn_strategy_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_strategy_trace_t *t = va_arg (*args, hicn_strategy_trace_t *);

  const hicn_strategy_vft_t *vft = hicn_dpo_get_strategy_vft (t->dpo_type);

  return vft->hicn_format_strategy_trace (s, t);
}

always_inline void
drop_packet (vlib_main_t *vm, u32 bi0, u32 *n_left_to_next, u32 *next0,
	     u32 **to_next, u32 *next_index, vlib_node_runtime_t *node)
{
  *next0 = HICN_STRATEGY_NEXT_ERROR_DROP;

  (*to_next)[0] = bi0;
  *to_next += 1;
  *n_left_to_next -= 1;

  vlib_validate_buffer_enqueue_x1 (vm, node, *next_index, *to_next,
				   *n_left_to_next, bi0, *next0);
}

/*
 * ICN strategy later node for interests: - 1 packet at a time - ipv4/tcp
 * ipv6/tcp
 */
uword
hicn_strategy_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame)
{

  int ret;
  u32 n_left_from, *from, *to_next, n_left_to_next;
  hicn_strategy_next_t next_index;
  hicn_strategy_runtime_t *rt = NULL;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  f64 tnow;
  vlib_buffer_t *b0;
  u32 bi0;
  hicn_face_id_t outfaces[MAX_OUT_FACES];
  u32 clones[MAX_OUT_FACES];
  u16 outfaces_len;
  u32 next0;
  const hicn_dpo_ctx_t *dpo_ctx;
  const hicn_strategy_vft_t *strategy;
  hicn_buffer_t *hicnb0;
  hicn_pcs_entry_t *pcs_entry = NULL;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = (hicn_strategy_next_t) node->cached_next_index;
  rt = vlib_node_get_runtime_data (vm, hicn_strategy_node.index);
  rt->pitcs = &hicn_main.pitcs;
  /* Capture time in vpp terms */
  tnow = vlib_time_now (vm);
  next0 = next_index;

  while (n_left_from > 0)
    {

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  // Prefetch for next iteration
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    }

	  // Dequeue a packet buffer
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  b0 = vlib_get_buffer (vm, bi0);

	  // Drop by default
	  next0 = HICN_STRATEGY_NEXT_ERROR_DROP;

	  // Increment counters
	  stats.pkts_processed++;

	  hicnb0 = hicn_get_buffer (b0);

	  // Get the strategy VFT
	  hicnb0->dpo_ctx_id = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	  dpo_ctx = hicn_strategy_dpo_ctx_get (hicnb0->dpo_ctx_id);
	  hicnb0->vft_id = dpo_ctx->dpo_type;
	  strategy = hicn_dpo_get_strategy_vft (hicnb0->vft_id);
	  strategy->hicn_add_interest (hicnb0->dpo_ctx_id);

	  // Check we have at least one next hop for the packet
	  ret = strategy->hicn_select_next_hop (hicnb0->dpo_ctx_id, outfaces,
						&outfaces_len);

	  if (PREDICT_FALSE (ret != HICN_ERROR_NONE || outfaces_len == 0))
	    {
	      drop_packet (vm, bi0, &n_left_from, &next0, &to_next,
			   &next_index, node);
	      continue;
	    }

	  // Create a new PIT entry
	  pcs_entry = hicn_pcs_entry_pit_get (rt->pitcs, tnow,
					      hicn_buffer_get_lifetime (b0));

	  // Add entry to PIT table
	  ret = hicn_pcs_pit_insert (rt->pitcs, pcs_entry, &hicnb0->name);

	  if (PREDICT_FALSE (ret != HICN_ERROR_NONE))
	    {
	      drop_packet (vm, bi0, &n_left_from, &next0, &to_next,
			   &next_index, node);
	      continue;
	    }

	  // Store internal state
	  ret = hicn_store_internal_state (
	    b0, hicn_pcs_entry_get_index (rt->pitcs, pcs_entry),
	    vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

	  if (PREDICT_FALSE (ret != HICN_ERROR_NONE))
	    {
	      hicn_pcs_entry_remove_lock (rt->pitcs, pcs_entry);
	      drop_packet (vm, bi0, &n_left_from, &next0, &to_next,
			   &next_index, node);
	      continue;
	    }

	  // Add face
	  hicn_pcs_entry_pit_add_face (pcs_entry, hicnb0->face_id);

	  // Set next node
	  next0 = hicn_buffer_is_v6 (b0) ? HICN_STRATEGY_NEXT_INTEREST_FACE6 :
						 HICN_STRATEGY_NEXT_INTEREST_FACE4;

	  if (PREDICT_TRUE (ret == HICN_ERROR_NONE))
	    {
	      // Clone interest if needed
	      if (outfaces_len > 1)
		{
		  ret = vlib_buffer_clone (vm, bi0, clones, (u16) outfaces_len,
					   CLIB_CACHE_LINE_BYTES * 2);
		  ASSERT (ret == outfaces_len);
		}
	      else
		{
		  clones[0] = bi0;
		}

	      // Send interest to next hops
	      for (u32 nh = 0; nh < outfaces_len; nh++)
		{
		  vlib_buffer_t *local_b0 = vlib_get_buffer (vm, clones[nh]);

		  to_next[0] = clones[nh];
		  to_next += 1;
		  n_left_to_next -= 1;

		  vnet_buffer (local_b0)->ip.adj_index[VLIB_TX] = outfaces[nh];
		  stats.pkts_interest_count++;

		  // Maybe trace
		  if (PREDICT_FALSE (
			(node->flags & VLIB_NODE_FLAG_TRACE) &&
			(local_b0->flags & VLIB_BUFFER_IS_TRACED)))
		    {
		      hicn_strategy_trace_t *t =
			vlib_add_trace (vm, node, local_b0, sizeof (*t));
		      t->pkt_type = HICN_PACKET_TYPE_DATA;
		      t->sw_if_index =
			vnet_buffer (local_b0)->sw_if_index[VLIB_RX];
		      t->next_index = next0;
		      t->dpo_type = hicnb0->vft_id;
		    }

		  /*
		   * Fix in case of a wrong speculation. Needed for
		   * cloning the data in the right frame
		   */
		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next,
						   clones[nh], next0);
		}
	    }
	  else
	    {
	      drop_packet (vm, bi0, &n_left_from, &next0, &to_next,
			   &next_index, node);
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, hicn_strategy_node.index,
			       HICNFWD_ERROR_PROCESSED, stats.pkts_processed);
  vlib_node_increment_counter (vm, hicn_strategy_node.index,
			       HICNFWD_ERROR_INTERESTS,
			       stats.pkts_interest_count);

  return (frame->n_vectors);
}

/*
 * Node registration for the forwarder node
 */
VLIB_REGISTER_NODE (hicn_strategy_node) =
  {
   .name = "hicn-strategy",
   .function = hicn_strategy_fn,
   .vector_size = sizeof (u32),
   .runtime_data_bytes = sizeof (int) + sizeof(hicn_pit_cs_t *),
   .format_trace = hicn_strategy_format_trace,
   .type = VLIB_NODE_TYPE_INTERNAL,
   .n_errors = ARRAY_LEN (hicn_strategy_error_strings),
   .error_strings = hicn_strategy_error_strings,
   .n_next_nodes = HICN_STRATEGY_N_NEXT,
   .next_nodes =
   {
    [HICN_STRATEGY_NEXT_INTEREST_HITPIT] = "hicn-interest-hitpit",
    [HICN_STRATEGY_NEXT_INTEREST_HITCS] = "hicn-interest-hitcs",
    [HICN_STRATEGY_NEXT_INTEREST_FACE4] = "hicn4-face-output",
    [HICN_STRATEGY_NEXT_INTEREST_FACE6] = "hicn6-face-output",
    [HICN_STRATEGY_NEXT_ERROR_DROP] = "error-drop",
   },
  };

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */