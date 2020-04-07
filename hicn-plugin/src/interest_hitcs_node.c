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

#include <vnet/ip/ip6_packet.h>
#include <vppinfra/string.h>

#include "interest_hitcs.h"
#include "mgmt.h"
#include "parser.h"
#include "data_fwd.h"
#include "infra.h"
#include "state.h"
#include "error.h"

/* packet trace format function */
static u8 *hicn_interest_hitcs_format_trace (u8 * s, va_list * args);


/* Stats string values */
static char *hicn_interest_hitcs_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

vlib_node_registration_t hicn_interest_hitcs_node;

always_inline void drop_packet (u32 * next0);

always_inline void
clone_from_cs (vlib_main_t * vm, u32 * bi0_cs, vlib_buffer_t * dest, u8 isv6)
{
  /* Retrieve the buffer to clone */
  vlib_buffer_t *cs_buf = vlib_get_buffer (vm, *bi0_cs);
  hicn_buffer_t *hicnb = hicn_get_buffer (cs_buf);
  word buffer_advance = CLIB_CACHE_LINE_BYTES * 2;
  if (hicnb->flags & HICN_BUFFER_FLAGS_PKT_LESS_TWO_CL)
    {
      clib_memcpy_fast (vlib_buffer_get_current (dest),
			vlib_buffer_get_current (cs_buf),
			cs_buf->current_length);
      clib_memcpy_fast (dest->opaque2, cs_buf->opaque2,
			sizeof (cs_buf->opaque2));

      dest->current_length = cs_buf->current_length;
      dest->total_length_not_including_first_buffer = 0;
    }
  else
    {
      vlib_buffer_advance (cs_buf, -buffer_advance);
      if (PREDICT_FALSE (cs_buf->ref_count == 255))
	{
	  vlib_buffer_t *cs_buf2 = vlib_buffer_copy (vm, cs_buf);
	  vlib_buffer_advance (cs_buf, buffer_advance);
	  *bi0_cs = vlib_get_buffer_index (vm, cs_buf2);
	  cs_buf->ref_count--;
	  cs_buf = cs_buf2;
	}

      clib_memcpy_fast (vlib_buffer_get_current (dest),
			vlib_buffer_get_current (cs_buf), buffer_advance);
      clib_memcpy_fast (dest->opaque2, cs_buf->opaque2,
			sizeof (cs_buf->opaque2));
      dest->current_length = buffer_advance;
      vlib_buffer_advance (cs_buf, buffer_advance);
      vlib_buffer_attach_clone (vm, dest, cs_buf);
    }
}

static uword
hicn_interest_hitcs_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  hicn_interest_hitcs_next_t next_index;
  hicn_interest_hitcs_runtime_t *rt;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  f64 tnow;
  int ret;

  rt = vlib_node_get_runtime_data (vm, hicn_interest_hitcs_node.index);

  if (PREDICT_FALSE (rt->pitcs == NULL))
    {
      rt->pitcs = &hicn_main.pitcs;
    }
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  /* Capture time in vpp terms */
  tnow = vlib_time_now (vm);
  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u8 isv6;
	  u8 *nameptr;
	  u16 namelen;
	  u32 bi0;
	  u32 next0 = HICN_INTEREST_HITCS_NEXT_ERROR_DROP;
	  hicn_name_t name;
	  hicn_header_t *hicn0;
	  hicn_buffer_t *hicnb0;
	  hicn_hash_node_t *node0;
	  hicn_pcs_entry_t *pitp;
	  hicn_hash_entry_t *hash_entry0;
	  const hicn_strategy_vft_t *strategy_vft0;
	  const hicn_dpo_vft_t *dpo_vft0;
	  u8 dpo_ctx_id0;

	  /* Prefetch for next iteration. */
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, 2 * CLIB_CACHE_LINE_BYTES, STORE);
	      CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, STORE);
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
	  hicn_get_internal_state (hicnb0, rt->pitcs, &node0, &strategy_vft0,
				   &dpo_vft0, &dpo_ctx_id0, &hash_entry0);

	  ret = hicn_interest_parse_pkt (b0, &name, &namelen, &hicn0, &isv6);
	  nameptr = (u8 *) (&name);
	  pitp = hicn_pit_get_data (node0);

	  dpo_id_t hicn_dpo_id0 =
	    { dpo_vft0->hicn_dpo_get_type (), 0, 0, dpo_ctx_id0 };

	  if (PREDICT_FALSE
	      (ret != HICN_ERROR_NONE ||
	       !hicn_node_compare (nameptr, namelen, node0)))
	    {
	      /* Remove lock from the entry */
	      hicn_pcs_remove_lock (rt->pitcs, &pitp, &node0, vm, hash_entry0,
				    dpo_vft0, &hicn_dpo_id0);
	      drop_packet (&next0);
	      goto end_processing;
	    }
	  if ((tnow > pitp->shared.expire_time))
	    {
	      /* Delete and clean up expired CS entry */
	      hicn_pcs_delete (rt->pitcs, &pitp, &node0, vm, hash_entry0,
			       dpo_vft0, &hicn_dpo_id0);
	      stats.cs_expired_count++;
	      /* Forward interest to the strategy node */
	      next0 = HICN_INTEREST_HITCS_NEXT_STRATEGY;
	    }
	  else
	    {
	      if (PREDICT_TRUE
		  (!(hash_entry0->he_flags & HICN_HASH_ENTRY_FLAG_DELETED)))
		hicn_pcs_cs_update (vm, rt->pitcs, pitp, pitp, node0);

	      /*
	       * Retrieve the incoming iface and forward
	       * the data through it
	       */
	      next0 = hicnb0->face_id;
	      vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
		isv6 ? HICN_INTEREST_HITCS_NEXT_IFACE6_OUT :
                HICN_INTEREST_HITCS_NEXT_IFACE4_OUT;

	      clone_from_cs (vm, &pitp->u.cs.cs_pkt_buf, b0, isv6);

	      stats.pkts_from_cache_count++;
	      stats.pkts_data_count++;
	      /* Remove lock from the entry */
	      hicn_pcs_remove_lock (rt->pitcs, &pitp, &node0, vm, hash_entry0,
				    dpo_vft0, &hicn_dpo_id0);
	    }

	end_processing:

	  /* Maybe trace */
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_interest_hitcs_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pkt_type = HICN_PKT_TYPE_INTEREST;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	    }
	  /* Incr packet counter */
	  stats.pkts_processed += 1;

	  /*
	   * Verify speculative enqueue, maybe switch current
	   * next frame
	   */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  u32 pit_int_count = hicn_pit_get_int_count (rt->pitcs);

  vlib_node_increment_counter (vm, hicn_interest_hitcs_node.index,
			       HICNFWD_ERROR_CACHED,
			       stats.pkts_from_cache_count);

  vlib_node_increment_counter (vm, hicn_interest_hitcs_node.index,
			       HICNFWD_ERROR_DATAS, stats.pkts_data_count);

  update_node_counter (vm, hicn_interest_hitcs_node.index,
		       HICNFWD_ERROR_INT_COUNT, pit_int_count);

  return (frame->n_vectors);
}

always_inline void
drop_packet (u32 * next0)
{
  *next0 = HICN_INTEREST_HITCS_NEXT_ERROR_DROP;
}

/* packet trace format function */
static u8 *
hicn_interest_hitcs_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_interest_hitcs_trace_t *t =
    va_arg (*args, hicn_interest_hitcs_trace_t *);

  s = format (s, "INTEREST-HITCS: pkt: %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn_interest_hitcs_node) =
{
  .function = hicn_interest_hitcs_node_fn,
  .name = "hicn-interest-hitcs",
  .vector_size = sizeof(u32),
  .runtime_data_bytes = sizeof(hicn_interest_hitcs_runtime_t),
  .format_trace = hicn_interest_hitcs_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn_interest_hitcs_error_strings),
  .error_strings = hicn_interest_hitcs_error_strings,
  .n_next_nodes = HICN_INTEREST_HITCS_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN_INTEREST_HITCS_NEXT_STRATEGY] = "hicn-strategy",
    [HICN_INTEREST_HITCS_NEXT_IFACE4_OUT] = "hicn4-iface-output",
    [HICN_INTEREST_HITCS_NEXT_IFACE6_OUT] = "hicn6-iface-output",
    [HICN_INTEREST_HITCS_NEXT_ERROR_DROP] = "error-drop"
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
