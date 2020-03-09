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

#include "hicn.h"
#include "parser.h"
#include "strategy.h"
#include "strategy_dpo_ctx.h"
#include "face_db.h"
#include "infra.h"
#include "mgmt.h"
#include "pcs.h"
#include "state.h"
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
hicn_strategy_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_strategy_trace_t *t = va_arg (*args, hicn_strategy_trace_t *);

  const hicn_strategy_vft_t *vft = hicn_dpo_get_strategy_vft (t->dpo_type);

  return vft->hicn_format_strategy_trace (s, t);
}


always_inline int
hicn_new_interest (hicn_strategy_runtime_t * rt, vlib_buffer_t * b0,
		   u32 * next, f64 tnow, u8 * nameptr,
		   u16 namelen, dpo_id_t * outface, int nh_idx,
		   index_t dpo_ctx_id0, const hicn_strategy_vft_t * strategy,
		   dpo_type_t dpo_type, u8 isv6,
		   vl_api_hicn_api_node_stats_get_reply_t * stats)
{
  int ret;
  hicn_hash_node_t *nodep;
  hicn_pcs_entry_t *pitp;
  hicn_header_t *hicn0;
  hicn_main_t *sm = &hicn_main;
  hicn_buffer_t *hicnb0 = hicn_get_buffer (b0);
  u32 node_id0 = 0;
  u8 vft_id0 = dpo_type;
  u8 is_cs0 = 0;
  u8 hash_entry_id = 0;
  u8 bucket_is_overflow = 0;
  u32 bucket_id = ~0;


  /* Create PIT node and init PIT entry */
  nodep = hicn_hashtb_alloc_node (rt->pitcs->pcs_table);
  if (PREDICT_FALSE (nodep == NULL))
    {
      /* Nothing we can do - no mem */
      *next = HICN_STRATEGY_NEXT_ERROR_DROP;
      return HICN_ERROR_HASHTB_NOMEM;
    }
  pitp = hicn_pit_get_data (nodep);
  hicn_pit_init_data (pitp);
  pitp->shared.create_time = tnow;

  hicn0 = vlib_buffer_get_current (b0);
  hicn_lifetime_t imsg_lifetime;
  hicn_type_t type = hicnb0->type;
  hicn_ops_vft[type.l1]->get_lifetime (type, &hicn0->protocol,
				       &imsg_lifetime);

  if (imsg_lifetime > sm->pit_lifetime_max_ms)
    {
      imsg_lifetime = sm->pit_lifetime_max_ms;
    }
  pitp->shared.expire_time = hicn_pcs_get_exp_time (tnow, imsg_lifetime);

  /* Set up the hash node and insert it */
  hicn_hash_entry_t *hash_entry;
  hicn_hashtb_init_node (rt->pitcs->pcs_table, nodep, nameptr, namelen);

  ret =
    hicn_pcs_pit_insert (rt->pitcs, pitp, nodep, &hash_entry,
			 hicnb0->name_hash, &node_id0, &dpo_ctx_id0, &vft_id0,
			 &is_cs0, &hash_entry_id, &bucket_id,
			 &bucket_is_overflow);

  if (ret == HICN_ERROR_NONE)
    {
      strategy->hicn_add_interest (vnet_buffer (b0)->ip.adj_index[VLIB_TX],
				   hash_entry);

      /* Add face */
      hicn_face_db_add_face_dpo (&hicnb0->face_dpo_id, &(pitp->u.pit.faces));

      /* Remove lock on the dpo stored in the vlib_buffer */
      //dpo_unlock (&hicnb0->face_dpo_id);

      *next = outface->dpoi_next_node;

      vnet_buffer (b0)->ip.adj_index[VLIB_TX] = outface->dpoi_index;
      stats->pkts_interest_count++;
    }
  else
    {
      /* Interest aggregate in PIT */
      if (ret == HICN_ERROR_HASHTB_EXIST)
	{
	  hicn_store_internal_state (b0, hicnb0->name_hash, node_id0,
				     dpo_ctx_id0, vft_id0, hash_entry_id,
				     bucket_id, bucket_is_overflow);
	  // We need to take a lock as the lock is not taken on the hash
	  // entry because it is a CS entry (hash_insert function).
	  hash_entry->locks++;
	  *next =
	    is_cs0 ? HICN_STRATEGY_NEXT_INTEREST_HITCS :
	    HICN_STRATEGY_NEXT_INTEREST_HITPIT;
	}
      else
	{
	  /* Send the packet to the interest-hitpit node */
	  *next = HICN_STRATEGY_NEXT_ERROR_DROP;
	}
      hicn_faces_flush (&(pitp->u.pit.faces));
      hicn_hashtb_free_node (rt->pitcs->pcs_table, nodep);
    }

  return (ret);

}

/*
 * ICN strategy later node for interests: - 1 packet at a time - ipv4/tcp
 * ipv6/tcp
 */
uword
hicn_strategy_fn (vlib_main_t * vm,
		  vlib_node_runtime_t * node, vlib_frame_t * frame)
{

  u32 n_left_from, *from, *to_next, n_left_to_next;
  hicn_strategy_next_t next_index;
  hicn_strategy_runtime_t *rt = NULL;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  f64 tnow;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = (hicn_strategy_next_t) node->cached_next_index;
  rt = vlib_node_get_runtime_data (vm, hicn_strategy_node.index);
  rt->pitcs = &hicn_main.pitcs;
  /* Capture time in vpp terms */
  tnow = vlib_time_now (vm);

  while (n_left_from > 0)
    {

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u8 isv6;
	  u8 *nameptr;
	  u16 namelen;
	  hicn_name_t name;
	  hicn_header_t *hicn0;
	  vlib_buffer_t *b0;
	  u32 bi0;
	  dpo_id_t *outface = NULL;
	  int nh_idx;
	  u32 next0 = next_index;
	  int ret;

	  /* Prefetch for next iteration. */
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (&b1->trace_handle, 2 * CLIB_CACHE_LINE_BYTES,
			     STORE);
	    }
	  /* Dequeue a packet buffer */
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  next0 = HICN_STRATEGY_NEXT_ERROR_DROP;

	  hicn_dpo_ctx_t *dpo_ctx =
	    hicn_strategy_dpo_ctx_get (vnet_buffer (b0)->ip.
				       adj_index[VLIB_TX]);
	  const hicn_strategy_vft_t *strategy =
	    hicn_dpo_get_strategy_vft (dpo_ctx->dpo_type);

	  ret = hicn_interest_parse_pkt (b0, &name, &namelen, &hicn0, &isv6);
	  stats.pkts_processed++;
	  /* Select next hop */
	  /*
	   * Double check that the interest has been through
	   * the interest-pcslookup node due to misconfiguration in
	   * the punting rules.
	   */
	  if (PREDICT_TRUE
	      (ret == HICN_ERROR_NONE && HICN_IS_NAMEHASH_CACHED (b0)
	       && strategy->hicn_select_next_hop (vnet_buffer (b0)->
						  ip.adj_index[VLIB_TX],
						  &nh_idx,
						  &outface) ==
	       HICN_ERROR_NONE))
	    {
	      /*
	       * No need to check if parsing was successful
	       * here. Already checked in the interest_pcslookup
	       * node
	       */
	      nameptr = (u8 *) (&name);
	      hicn_new_interest (rt, b0, &next0, tnow, nameptr, namelen,
				 outface, nh_idx,
				 vnet_buffer (b0)->ip.adj_index[VLIB_TX],
				 strategy, dpo_ctx->dpo_type, isv6, &stats);
	    }
	  /* Maybe trace */
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_strategy_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pkt_type = HICN_PKT_TYPE_CONTENT;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      t->dpo_type = dpo_ctx->dpo_type;
	    }
	  /*
	   * Verify speculative enqueue, maybe switch current
	   * next frame
	   */
	  /*
	   * Fix in case of a wrong speculation. Needed for
	   * cloning the data in the right frame
	   */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
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
/* *INDENT-OFF* */
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
    [HICN_STRATEGY_NEXT_ERROR_DROP] = "error-drop",
   },
  };


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
