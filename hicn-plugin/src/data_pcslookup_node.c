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

#include "data_pcslookup.h"
#include "infra.h"
#include "mgmt.h"
#include "parser.h"
#include "state.h"
#include "strategy.h"
#include "strategy_dpo_manager.h"

/* Stats string values */
static char *hicn_data_pcslookup_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

/* packet trace format function */
always_inline u8 *hicn_data_pcslookup_format_trace (u8 *s, va_list *args);

vlib_node_registration_t hicn_data_pcslookup_node;

/*
 * hICN node for handling data. It performs a lookup in the PIT.
 */
static uword
hicn_data_pcslookup_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			     vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  hicn_data_pcslookup_next_t next_index;
  hicn_data_pcslookup_runtime_t *rt;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  vlib_buffer_t *b0;
  u32 bi0;
  u32 next0 = HICN_DATA_PCSLOOKUP_NEXT_ERROR_DROP;
  hicn_pcs_entry_t *pcs_entry = NULL;
  hicn_buffer_t *hicnb0;
  int ret;

  rt = vlib_node_get_runtime_data (vm, node->node_index);

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
	  // Prefetch for next iteration.
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      // Prefetch two cache lines-- 128 byte-- so that we load the
	      // hicn_buffer_t as well
	      CLIB_PREFETCH (b1, 2 * CLIB_CACHE_LINE_BYTES, STORE);
	    }

	  // Dequeue a packet buffer
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  hicnb0 = hicn_get_buffer (b0);

	  // By default go to drop
	  next0 = HICN_DATA_PCSLOOKUP_NEXT_ERROR_DROP;

	  // Increase packet counters
	  stats.pkts_processed += 1;
	  stats.pkts_data_count += 1;

	  // Lookup the name in the PIT
	  ret = hicn_pcs_lookup_one (rt->pitcs, hicn_buffer_get_name (b0),
				     &pcs_entry);

	  if (ret == HICN_ERROR_NONE)
	    {
	      ret = hicn_store_internal_state (
		b0, hicn_pcs_entry_get_index (rt->pitcs, pcs_entry),
		hicnb0->dpo_ctx_id);

	      /*
	       * In case the result of the lookup
	       * is a CS entry, the packet is
	       * dropped
	       */
	      next0 = HICN_DATA_PCSLOOKUP_NEXT_DATA_FWD +
		      (hicn_pcs_entry_is_cs (pcs_entry) && !ret);
	    }

	  /*
	   * Verify speculative enqueue, maybe switch current
	   * next frame
	   */
	  /*
	   * Fix in case of a wrong speculation. Needed to
	   * clone the data in the right frame
	   */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  /* Maybe trace */
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_data_pcslookup_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pkt_type = HICN_PACKET_TYPE_DATA;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Check the CS LRU, and trim if necessary. */
  u32 pit_int_count = hicn_pcs_get_pit_count (rt->pitcs);
  u32 pit_cs_count = hicn_pcs_get_cs_count (rt->pitcs);

  vlib_node_increment_counter (vm, hicn_data_pcslookup_node.index,
			       HICNFWD_ERROR_PROCESSED, stats.pkts_processed);

  vlib_node_increment_counter (vm, hicn_data_pcslookup_node.index,
			       HICNFWD_ERROR_DATAS, stats.pkts_data_count);

  update_node_counter (vm, hicn_data_pcslookup_node.index,
		       HICNFWD_ERROR_INT_COUNT, pit_int_count);
  update_node_counter (vm, hicn_data_pcslookup_node.index,
		       HICNFWD_ERROR_CS_COUNT, pit_cs_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn_data_pcslookup_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_data_pcslookup_trace_t *t =
    va_arg (*args, hicn_data_pcslookup_trace_t *);

  s = format (s, "DATA-PCSLOOKUP: pkt: %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);
  return (s);
}

/*
 * Node registration for the data forwarder node
 */
VLIB_REGISTER_NODE(hicn_data_pcslookup_node) =
{
  .function = hicn_data_pcslookup_node_fn,
  .name = "hicn-data-pcslookup",
  .vector_size = sizeof(u32),
  .runtime_data_bytes = sizeof(hicn_data_pcslookup_runtime_t),
  .format_trace = hicn_data_pcslookup_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn_data_pcslookup_error_strings),
  .error_strings = hicn_data_pcslookup_error_strings,
  .n_next_nodes = HICN_DATA_PCSLOOKUP_N_NEXT,
  .next_nodes = {
    [HICN_DATA_PCSLOOKUP_NEXT_DATA_FWD] = "hicn-data-fwd",
    [HICN_DATA_PCSLOOKUP_NEXT_ERROR_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */