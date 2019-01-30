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
#include "strategy_dpo_ctx.h"
#include "infra.h"
#include "mgmt.h"
#include "pcs.h"

/*
 * Node context data (to be used in all the strategy nodes); we think this is
 * per-thread/instance
 */
typedef struct hicn_data_push_runtime_s
{
  int id;
  hicn_pit_cs_t *pitcs;
} hicn_data_push_runtime_t;

/* Stats string values */
static char *hicn_data_push_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

typedef enum
{
  HICN_DATA_PUSH_NEXT_ERROR_DROP,
  HICN_DATA_PUSH_N_NEXT,
} hicn_data_push_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[40];
} hicn_data_push_trace_t;

vlib_node_registration_t hicn_data_push_node;

always_inline void
prep_buffer_for_cs (vlib_main_t * vm, vlib_buffer_t * b0, u8 isv6)
{
  if (isv6)
    {
      /* Advance the vlib buffer to the beginning of the TCP header */
      vlib_buffer_advance (b0, sizeof (ip6_header_t) + sizeof (tcp_header_t));
      b0->total_length_not_including_first_buffer = 0;
    }
  else
    {
      /* Advance the vlib buffer to the beginning of the TCP header */
      vlib_buffer_advance (b0, sizeof (ip4_header_t) + sizeof (tcp_header_t));
      b0->total_length_not_including_first_buffer = 0;
    }
}

always_inline int
hicn_new_data (vlib_main_t * vm, hicn_data_push_runtime_t * rt,
	       vlib_buffer_t * b0, u32 * next, f64 tnow, u8 * nameptr,
	       u16 namelen, u8 isv6)
{
  int ret;
  hicn_hash_node_t *nodep;
  hicn_pcs_entry_t *pitp;
  hicn_header_t *hicn0;
  hicn_buffer_t *hicnb0 = hicn_get_buffer (b0);
  u32 node_id0 = 0;
  u8 dpo_ctx_id0 = 0;
  u8 vft_id0 = 0;
  u8 is_cs0 = 0;
  u8 hash_entry_id = 0;
  u32 bucket_id = ~0;
  u8 bucket_is_overflow = 0;
  hicn_lifetime_t dmsg_lifetime;

  /* Create PIT node and init PIT entry */
  nodep = hicn_hashtb_alloc_node (rt->pitcs->pcs_table);
  if (PREDICT_FALSE (nodep == NULL))
    {
      /* Nothing we can do - no mem */
      *next = HICN_DATA_PUSH_NEXT_ERROR_DROP;
      return HICN_ERROR_HASHTB_NOMEM;
    }
  pitp = hicn_pit_get_data (nodep);
  hicn_pit_init_data (pitp);
  pitp->shared.create_time = tnow;

  hicn0 = vlib_buffer_get_current (b0);

  hicn_type_t type = hicnb0->type;
  hicn_ops_vft[type.l1]->get_lifetime (type, &hicn0->protocol,
				       &dmsg_lifetime);

  if (dmsg_lifetime < HICN_PARAM_CS_LIFETIME_MIN
      || dmsg_lifetime > HICN_PARAM_CS_LIFETIME_MAX)
    {
      dmsg_lifetime = HICN_PARAM_CS_LIFETIME_DFLT;
    }
  pitp->shared.expire_time = hicn_pcs_get_exp_time (tnow, dmsg_lifetime);
  prep_buffer_for_cs (vm, b0, isv6);

  /* Store the original packet buffer in the CS node */
  pitp->u.cs.cs_pkt_buf = vlib_get_buffer_index (vm, b0);

  pitp->u.cs.cs_rxface = hicnb0->face_dpo_id;

  /* Set up the hash node and insert it */
  hicn_hashtb_init_node (rt->pitcs->pcs_table, nodep, nameptr, namelen);


  nodep->hn_flags |= HICN_HASH_NODE_CS_FLAGS;
  pitp->shared.entry_flags |= HICN_PCS_ENTRY_CS_FLAG;

  hicn_hash_entry_t *hash_entry;
  ret =
    hicn_pcs_cs_insert_update (vm, rt->pitcs, pitp, nodep, &hash_entry,
			       hicnb0->name_hash, &node_id0, &dpo_ctx_id0,
			       &vft_id0, &is_cs0, &hash_entry_id, &bucket_id,
			       &bucket_is_overflow);

  hash_entry->he_flags |= HICN_HASH_ENTRY_FLAG_CS_ENTRY;
  if (ret != HICN_ERROR_NONE)
    {
      hicn_hashtb_free_node (rt->pitcs->pcs_table, nodep);
    }
  return (ret);

}

/*
 * ICN strategy later node for interests: - 1 packet at a time - ipv4/tcp
 * ipv6/tcp
 */
uword
hicn_data_push_fn (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{

  u32 n_left_from, *from, *to_next, n_left_to_next;
  hicn_data_push_next_t next_index;
  hicn_data_push_runtime_t *rt;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  f64 tnow;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = (hicn_data_push_next_t) node->cached_next_index;
  rt = vlib_node_get_runtime_data (vm, hicn_data_push_node.index);
  rt->pitcs = &hicn_main.pitcs;
  /* Capture time in vpp terms */
  tnow = vlib_time_now (vm);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop, X2 */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u8 isv6_0, isv6_1;
	  u8 *nameptr0, *nameptr1;
	  u16 namelen0, namelen1;
	  hicn_name_t name0, name1;
	  hicn_header_t *hicn0, *hicn1;
	  vlib_buffer_t *b0, *b1;
	  u32 bi0, bi1;
	  u32 next0 = next_index, next1 = next_index;
	  int ret0, ret1;

	  /* Prefetch for next iteration. */
	  {
	    vlib_buffer_t *b2, *b3;
	    b2 = vlib_get_buffer (vm, from[2]);
	    b3 = vlib_get_buffer (vm, from[3]);
	    CLIB_PREFETCH (b2, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (b3, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	    CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  /* Dequeue a packet buffer */
	  bi0 = from[0];
	  bi1 = from[1];
	  from += 2;
	  n_left_from -= 2;
	  /* to_next[0] = bi0; */
	  /* to_next[1] = bi1; */
	  /* to_next += 2; */
	  /* n_left_to_next -= 2; */

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  next0 = next1 = HICN_DATA_PUSH_NEXT_ERROR_DROP;

	  ret0 = hicn_data_parse_pkt (b0, &name0, &namelen0, &hicn0, &isv6_0);
	  ret1 = hicn_data_parse_pkt (b1, &name1, &namelen1, &hicn1, &isv6_1);

	  nameptr0 = (u8 *) (&name0);
	  nameptr1 = (u8 *) (&name1);
	  if (PREDICT_TRUE (ret0 == HICN_ERROR_NONE))
	    hicn_new_data (vm, rt, b0, &next0, tnow, nameptr0, namelen0,
			   isv6_0);

	  if (PREDICT_TRUE (ret1 == HICN_ERROR_NONE))
	    hicn_new_data (vm, rt, b1, &next1, tnow, nameptr1, namelen1,
			   isv6_1);
	  stats.pkts_data_count += 2;

	  /* Maybe trace */
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_data_push_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pkt_type = HICN_PKT_TYPE_CONTENT;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];;
	      t->next_index = next0;
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_data_push_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->pkt_type = HICN_PKT_TYPE_CONTENT;
	      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];;
	      t->next_index = next0;
	    }
	}

      /* Dual loop, X1 */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u8 isv6;
	  u8 *nameptr;
	  u16 namelen;
	  hicn_name_t name;
	  hicn_header_t *hicn0;
	  vlib_buffer_t *b0;
	  u32 bi0;
	  u32 next0 = next_index;
	  int ret0;

	  /* Prefetch for next iteration. */
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      //hicn_buffer_t * hicnb1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, LOAD);
	      CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, STORE);
	    }
	  /* Dequeue a packet buffer */
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  next0 = HICN_DATA_PUSH_NEXT_ERROR_DROP;

	  ret0 = hicn_data_parse_pkt (b0, &name, &namelen, &hicn0, &isv6);
	  nameptr = (u8 *) (&name);

	  if (PREDICT_TRUE (ret0 == HICN_ERROR_NONE))
	    hicn_new_data (vm, rt, b0, &next0, tnow, nameptr, namelen, isv6);
	  stats.pkts_data_count++;

	  /* Maybe trace */
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_data_push_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pkt_type = HICN_PKT_TYPE_CONTENT;
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];;
	      t->next_index = next0;
	    }
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, hicn_data_push_node.index,
			       HICNFWD_ERROR_CACHED, stats.pkts_data_count);

  return (frame->n_vectors);
}

/* packet trace format function */
always_inline u8 *
hicn_data_push_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_data_push_trace_t *t = va_arg (*args, hicn_data_push_trace_t *);

  s = format (s, "DATA-STORE: pkt: %d, sw_if_index %d, next index %d\n",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);

  return (s);
}


/*
 * Node registration for the data forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn_data_push_node) =
{
	.function = hicn_data_push_fn,
		.name = "hicn-data-push",
		.vector_size = sizeof(u32),
		.runtime_data_bytes = sizeof(hicn_data_push_runtime_t),
		.format_trace = hicn_data_push_format_trace,
		.type = VLIB_NODE_TYPE_INTERNAL,
		.n_errors = ARRAY_LEN(hicn_data_push_error_strings),
		.error_strings = hicn_data_push_error_strings,
		.n_next_nodes = HICN_DATA_PUSH_N_NEXT,
	/* edit / add dispositions here */
		.next_nodes = {
		[HICN_DATA_PUSH_NEXT_ERROR_DROP] = "error-drop",
	},
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
