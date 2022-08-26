/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include "interest_pcslookup.h"
#include "mgmt.h"
#include "parser.h"
#include "infra.h"
#include "strategy_dpo_manager.h"
#include "error.h"
#include "state.h"

#include <hicn/interest_manifest.h>

/**
 * @FILE This node performs a lookup in the PIT and CS for a received interest
 * packet.
 *
 * This node passes the packet to the interest-hitpit and interest-hitcs nodes
 * when there is a hit in the pit or content store, respectively.
 */

/* Functions declarations */

/* packet trace format function */
static u8 *hicn_interest_pcslookup_format_trace (u8 *s, va_list *args);

/* Stats string values */
static char *hicn_interest_pcslookup_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

vlib_node_registration_t hicn_interest_pcslookup_node;

/*
 * ICN forwarder node for interests.
 */
static uword
hicn_interest_pcslookup_node_inline (vlib_main_t *vm,
				     vlib_node_runtime_t *node,
				     vlib_frame_t *frame)
{
  int ret;
  u32 n_left_from, *from, *to_next;
  hicn_interest_pcslookup_next_t next_index;
  hicn_interest_pcslookup_runtime_t *rt;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  vlib_buffer_t *b0;
  u32 bi0;
  u32 next0 = HICN_INTEREST_PCSLOOKUP_NEXT_ERROR_DROP;
  hicn_pcs_entry_t *pcs_entry = NULL;

  rt = vlib_node_get_runtime_data (vm, hicn_interest_pcslookup_node.index);

  if (PREDICT_FALSE (rt->pitcs == NULL))
    {
      rt->pitcs = &hicn_main.pitcs;
    }
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  /* Prefetch for next iteration. */
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, STORE);
	    }

	  // Dequeue a packet buffer
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  // By default we send the interest to drop
	  next0 = HICN_INTEREST_PCSLOOKUP_NEXT_STRATEGY;

	  // Update stats
	  stats.pkts_processed++;

	  // Check if the interest is in the PCS already
	  hicn_name_t name;
	  hicn_packet_get_name (&hicn_get_buffer (b0)->pkbuf, &name);
	  ret = hicn_pcs_lookup_one (rt->pitcs, &name, &pcs_entry);
	  //&hicn_get_buffer (b0)->name,

	  if (ret == HICN_ERROR_NONE)
	    {
	      // We found an entry in the PCS. Next stage for this packet is
	      // one of hitpit/cs nodes
	      next0 = HICN_INTEREST_PCSLOOKUP_NEXT_INTEREST_HITPIT +
		      hicn_pcs_entry_is_cs (pcs_entry);

	      ret = hicn_store_internal_state (
		b0, hicn_pcs_entry_get_index (rt->pitcs, pcs_entry),
		vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

	      if (PREDICT_FALSE (ret != HICN_ERROR_NONE))
		next0 = HICN_INTEREST_PCSLOOKUP_NEXT_ERROR_DROP;
	    }

	  stats.pkts_interest_count++;

	  // Interest manifest?
	  if (hicn_buffer_get_payload_type (b0) == HPT_MANIFEST)
	    {
	      ;
	    }

	  // Maybe trace
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_interest_pcslookup_trace_t *t =
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
  u32 pit_cs_count = hicn_pcs_get_cs_count (rt->pitcs);

  vlib_node_increment_counter (vm, hicn_interest_pcslookup_node.index,
			       HICNFWD_ERROR_PROCESSED, stats.pkts_processed);

  vlib_node_increment_counter (vm, hicn_interest_pcslookup_node.index,
			       HICNFWD_ERROR_INTERESTS,
			       stats.pkts_interest_count);

  update_node_counter (vm, hicn_interest_pcslookup_node.index,
		       HICNFWD_ERROR_INT_COUNT, pit_int_count);

  update_node_counter (vm, hicn_interest_pcslookup_node.index,
		       HICNFWD_ERROR_CS_COUNT, pit_cs_count);

  return (frame->n_vectors);
}

/*
 * ICN forwarder node for interests manifest
 */
static uword
hicn_interest_manifest_pcslookup_node_inline (vlib_main_t *vm,
					      vlib_node_runtime_t *node,
					      vlib_frame_t *frame)
{
  int ret;
  u32 n_left_from, *from, *to_next;
  hicn_interest_pcslookup_next_t next_index;
  hicn_interest_pcslookup_runtime_t *rt;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  vlib_buffer_t *b0;
  hicn_buffer_t *hicnb0;
  u32 bi0;

  const hicn_dpo_ctx_t *dpo_ctx;
  const hicn_strategy_vft_t *strategy;

  u16 outfaces_len;

  // For cloning
  u32 clones[MAX_OUT_FACES];
  hicn_face_id_t outfaces[MAX_OUT_FACES];
  u32 next0 = HICN_INTEREST_PCSLOOKUP_NEXT_ERROR_DROP;
  hicn_pcs_entry_t *pcs_entry = NULL;
  interest_manifest_header_t *int_manifest_header = NULL;
  int pos = 0;

  rt = vlib_node_get_runtime_data (vm, hicn_interest_pcslookup_node.index);

  if (PREDICT_FALSE (rt->pitcs == NULL))
    {
      rt->pitcs = &hicn_main.pitcs;
    }
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  int forward = 0;

  vlib_buffer_t *cloneb;

  // Register now
  f64 tnow = vlib_time_now (vm);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  /* Prefetch for next iteration. */
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, STORE);
	    }

	  // Dequeue a packet buffer
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  hicnb0 = hicn_get_buffer (b0);

	  // By default we send the interest to drop node
	  next0 = HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_ERROR_DROP;

	  // Update stats
	  stats.pkts_processed++;

	  // Do not forward by default
	  forward = 0;

	  // Check if the interest is in the PCS already
	  hicn_name_t name;
	  hicn_packet_get_name (&hicn_get_buffer (b0)->pkbuf, &name);

	  ASSERT (hicn_buffer_get_payload_type (b0) == HPT_MANIFEST);

	  // Process interest manifest
	  u8 *payload;
	  size_t payload_size;
	  hicn_interest_get_payload (&hicn_get_buffer (b0)->pkbuf, &payload,
				     &payload_size, 0);
	  int_manifest_header = (interest_manifest_header_t *) (payload);

	  // Deserialize interest manifest
	  interest_manifest_deserialize (int_manifest_header);

	  hicn_name_suffix_t *suffix;
	  if (interest_manifest_is_valid (int_manifest_header, payload_size))
	    {
	      interest_manifest_foreach_suffix (int_manifest_header, suffix,
						pos)
		{
		  name.suffix = *suffix;
		  ret = hicn_pcs_lookup_one (rt->pitcs, &name, &pcs_entry);

		  if (ret == HICN_ERROR_NONE)
		    {
		      // Match in PCS. We need to clone a packet for the
		      // interest_hic{pit,cs} nodes.

		      next0 = HICN_INTEREST_PCSLOOKUP_NEXT_INTEREST_HITPIT +
			      hicn_pcs_entry_is_cs (pcs_entry);

		      vlib_buffer_clone (vm, bi0, clones, 1, 0);
		      cloneb = vlib_get_buffer (vm, clones[0]);

		      ret = hicn_store_internal_state (
			cloneb,
			hicn_pcs_entry_get_index (rt->pitcs, pcs_entry),
			vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

		      if (PREDICT_FALSE (ret != HICN_ERROR_NONE))
			next0 = HICN_INTEREST_PCSLOOKUP_NEXT_ERROR_DROP;

		      to_next[0] = clones[0];
		      to_next += 1;
		      n_left_to_next -= 1;

		      // Distinguish between aggregation or retransmission
		      ret = hicn_pcs_entry_pit_search (
			pcs_entry, hicn_get_buffer (b0)->face_id);
		      if (!ret)
			{
			  // Aggregated interest. Unset the corresponding
			  // position in bitmap.
			  bitmap_unset_no_check (
			    int_manifest_header->request_bitmap, pos);
			}
		      else
			{
			  // Interest must be forwarded fo face node as it
			  // contains retransmissions
			  forward = 1;
			}

		      // Maybe trace
		      if (PREDICT_FALSE (
			    (node->flags & VLIB_NODE_FLAG_TRACE) &&
			    (b0->flags & VLIB_BUFFER_IS_TRACED)))
			{
			  hicn_interest_pcslookup_trace_t *t =
			    vlib_add_trace (vm, node, b0, sizeof (*t));
			  t->pkt_type = HICN_PACKET_TYPE_INTEREST;
			  t->sw_if_index =
			    vnet_buffer (b0)->sw_if_index[VLIB_RX];
			  t->next_index = next0;
			}
		      /*
		       * Verify speculative enqueue, maybe switch current
		       * next frame
		       */
		      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						       to_next, n_left_to_next,
						       clones[0], next0);
		    }
		  else
		    {
		      // No match. Create new pcs entry and set interest to be
		      // forwarded
		      pcs_entry = hicn_pcs_entry_pit_get (
			rt->pitcs, tnow, hicn_buffer_get_lifetime (b0));

		      // Add entry to PCS table
		      ret = hicn_pcs_pit_insert (rt->pitcs, pcs_entry, &name);

		      // This cannot fail as we just checked if PCS contains
		      // this entry
		      assert (ret == HICN_ERROR_NONE);

		      // Store internal state
		      ret = hicn_store_internal_state (
			b0, hicn_pcs_entry_get_index (rt->pitcs, pcs_entry),
			vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

		      if (PREDICT_FALSE (ret != HICN_ERROR_NONE))
			{
			  // Remove entry
			  hicn_pcs_entry_remove_lock (rt->pitcs, pcs_entry);
			  // We do not drop the packet as it is an interest
			  // manifest.
			  continue;
			}

		      // Add face
		      hicn_pcs_entry_pit_add_face (
			pcs_entry, hicn_get_buffer (b0)->face_id);

		      forward = 1;
		    }
		}
	    }
	  else
	    {
	      next0 = HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_ERROR_DROP;
	    }

	  // If interest must be forwarded, let's do it now
	  if (forward)
	    {
	      // Serialize interest manifest again
	      interest_manifest_deserialize (int_manifest_header);

	      // Get the strategy VFT
	      hicnb0->dpo_ctx_id = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	      dpo_ctx = hicn_strategy_dpo_ctx_get (hicnb0->dpo_ctx_id);
	      hicnb0->vft_id = dpo_ctx->dpo_type;
	      strategy = hicn_dpo_get_strategy_vft (hicnb0->vft_id);
	      strategy->hicn_add_interest (hicnb0->dpo_ctx_id);

	      // Check we have at least one next hop for the packet
	      ret = strategy->hicn_select_next_hop (hicnb0->dpo_ctx_id,
						    outfaces, &outfaces_len);
	      if (ret == HICN_ERROR_NONE)
		{
		  next0 = hicn_buffer_is_v6 (b0) ?
				  HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_FACE6 :
				  HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_FACE4;

		  // Clone interest if needed
		  if (outfaces_len > 1)
		    {
		      ret =
			vlib_buffer_clone (vm, bi0, clones, (u16) outfaces_len,
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
		      vlib_buffer_t *local_b0 =
			vlib_get_buffer (vm, clones[nh]);

		      to_next[0] = clones[nh];
		      to_next += 1;
		      n_left_to_next -= 1;

		      vnet_buffer (local_b0)->ip.adj_index[VLIB_TX] =
			outfaces[nh];
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
		  next0 = HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_ERROR_DROP;

		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;

		  /*
		   * Fix in case of a wrong speculation. Needed for
		   * cloning the data in the right frame
		   */
		  vlib_validate_buffer_enqueue_x1 (
		    vm, node, next_index, to_next, n_left_to_next, bi0, next0);
		}
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  u32 pit_int_count = hicn_pcs_get_pit_count (rt->pitcs);
  u32 pit_cs_count = hicn_pcs_get_cs_count (rt->pitcs);

  vlib_node_increment_counter (vm, hicn_interest_pcslookup_node.index,
			       HICNFWD_ERROR_PROCESSED, stats.pkts_processed);

  vlib_node_increment_counter (vm, hicn_interest_pcslookup_node.index,
			       HICNFWD_ERROR_INTERESTS,
			       stats.pkts_interest_count);

  update_node_counter (vm, hicn_interest_pcslookup_node.index,
		       HICNFWD_ERROR_INT_COUNT, pit_int_count);

  update_node_counter (vm, hicn_interest_pcslookup_node.index,
		       HICNFWD_ERROR_CS_COUNT, pit_cs_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn_interest_pcslookup_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  const hicn_interest_pcslookup_trace_t *t =
    va_arg (*args, hicn_interest_pcslookup_trace_t *);

  s = format (s, "INTEREST_PCSLOOKUP: pkt: %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);
  return (s);
}

VLIB_NODE_FN (hicn_interest_pcslookup_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return hicn_interest_pcslookup_node_inline (vm, node, frame);
}

VLIB_NODE_FN (hicn_interest_manifest_pcslookup_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return hicn_interest_manifest_pcslookup_node_inline (vm, node, frame);
}

/*
 * Node registration for the interest forwarder node
 */
VLIB_REGISTER_NODE(hicn_interest_pcslookup_node) =
{
  .name = "hicn-interest-pcslookup",
  .vector_size = sizeof(u32),
  .runtime_data_bytes = sizeof(hicn_interest_pcslookup_runtime_t),
  .format_trace = hicn_interest_pcslookup_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn_interest_pcslookup_error_strings),
  .error_strings = hicn_interest_pcslookup_error_strings,
  .n_next_nodes = HICN_INTEREST_PCSLOOKUP_N_NEXT,
  .next_nodes =
  {
    [HICN_INTEREST_PCSLOOKUP_NEXT_STRATEGY] = "hicn-strategy",
    [HICN_INTEREST_PCSLOOKUP_NEXT_INTEREST_HITPIT] = "hicn-interest-hitpit",
    [HICN_INTEREST_PCSLOOKUP_NEXT_INTEREST_HITCS] = "hicn-interest-hitcs",
    [HICN_INTEREST_PCSLOOKUP_NEXT_ERROR_DROP] = "error-drop",
  },
};

/*
 * Node registration for the interest manifest forwarder node
 */
VLIB_REGISTER_NODE(hicn_interest_manifest_pcslookup_node) =
{
  .name = "hicn-interest-manifest-pcslookup",
  .vector_size = sizeof(u32),
  .runtime_data_bytes = sizeof(hicn_interest_pcslookup_runtime_t),
  .format_trace = hicn_interest_pcslookup_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn_interest_pcslookup_error_strings),
  .error_strings = hicn_interest_pcslookup_error_strings,
  .n_next_nodes = HICN_INTEREST_MANIFEST_PCSLOOKUP_N_NEXT,
  .next_nodes =
  {
    [HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_FACE4] = "hicn4-face-output",
    [HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_FACE6] = "hicn6-face-output",
    [HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_INTEREST_HITPIT] = "hicn-interest-hitpit",
    [HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_INTEREST_HITCS] = "hicn-interest-hitcs",
    [HICN_INTEREST_MANIFEST_PCSLOOKUP_NEXT_ERROR_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
