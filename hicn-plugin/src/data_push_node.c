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
#include "state.h"

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
  HICN_DATA_PUSH_NEXT_FWD,
  HICN_DATA_PUSH_NEXT_ERROR_DROP,
  HICN_DATA_PUSH_N_NEXT,
} hicn_data_push_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
} hicn_data_push_trace_t;

vlib_node_registration_t hicn_data_push_node;

always_inline void
prep_buffer_for_cs (vlib_main_t * vm, vlib_buffer_t * b0, u8 isv6)
{
  word buffer_advance = CLIB_CACHE_LINE_BYTES * 2;
  hicn_buffer_t *hicnb = hicn_get_buffer (b0);

  if (PREDICT_TRUE (b0->next_buffer == 0))
    {
      b0->total_length_not_including_first_buffer = 0;
      b0->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
    }

  /*
   * Mark the buffer as smaller than TWO_CL. It will be stored as is in the CS, without excluding
   * the hicn_header. Cloning is not possible, it will be copied.
   */
  if (b0->current_length <= (buffer_advance + (CLIB_CACHE_LINE_BYTES * 2)))
    {
      /* In this case the packet is copied. We don't need to add a reference as no buffer are
       * chained to it.
       */
      hicnb->flags |= HICN_BUFFER_FLAGS_PKT_LESS_TWO_CL;
    }
  else
    {
      vlib_buffer_advance (b0, buffer_advance);
    }
}

always_inline int
hicn_new_data (vlib_main_t * vm, hicn_data_push_runtime_t * rt,
	       vlib_buffer_t * b0, u32 ** to_forward, u32 * n_to_forward,
	       f64 tnow, u8 * nameptr, u16 namelen, u8 isv6)
{
  int ret;
  u32 bi0 = vlib_get_buffer_index (vm, b0);
  hicn_hash_node_t *nodep;
  hicn_pcs_entry_t *pitp;
  hicn_header_t *hicn0 = vlib_buffer_get_current (b0);
  hicn_buffer_t *hicnb0 = hicn_get_buffer (b0);
  u32 node_id0 = 0;
  index_t dpo_ctx_id0 = ~0;
  u8 vft_id0 = default_dpo.hicn_dpo_get_type ();
  u8 is_cs0 = 1;
  u8 hash_entry_id = 0;
  u32 bucket_id = ~0;
  u8 bucket_is_overflow = 0;
  hicn_lifetime_t dmsg_lifetime;

  hicnb0 = hicn_get_buffer (b0);
  hicn_type_t type = hicnb0->type;
  hicn_ops_vft[type.l1]->get_lifetime (type, &hicn0->protocol,
				       &dmsg_lifetime);

  if (!dmsg_lifetime)
    {
      vlib_buffer_free_one (vm, bi0);
      return HICN_ERROR_NONE;
    }

  /* Create PIT node and init PIT entry */
  nodep = hicn_hashtb_alloc_node (rt->pitcs->pcs_table);
  if (PREDICT_FALSE (nodep == NULL))
    {
      vlib_buffer_free_one (vm, bi0);
      /* Nothing we can do - no mem */
      return HICN_ERROR_HASHTB_NOMEM;
    }

  pitp = hicn_pit_get_data (nodep);
  hicn_cs_init_data (pitp);
  pitp->shared.create_time = tnow;

  if (dmsg_lifetime < HICN_PARAM_CS_LIFETIME_MIN
      || dmsg_lifetime > HICN_PARAM_CS_LIFETIME_MAX)
    {
      dmsg_lifetime = HICN_PARAM_CS_LIFETIME_DFLT;
    }
  pitp->shared.expire_time = hicn_pcs_get_exp_time (tnow, dmsg_lifetime);

  /* Store the original packet buffer in the CS node */
  pitp->u.cs.cs_pkt_buf = vlib_get_buffer_index (vm, b0);

  /* Set up the hash node and insert it */
  hicn_hashtb_init_node (rt->pitcs->pcs_table, nodep, nameptr, namelen);


  hicn_hash_entry_t *hash_entry;
  ret =
    hicn_pcs_cs_insert_update (vm, rt->pitcs, pitp, nodep, &hash_entry,
			       hicnb0->name_hash, &node_id0, &dpo_ctx_id0,
			       &vft_id0, &is_cs0, &hash_entry_id, &bucket_id,
			       &bucket_is_overflow, &(hicnb0->face_dpo_id));

  if (ret != HICN_ERROR_NONE)
    {
      hicn_hashtb_free_node (rt->pitcs->pcs_table, nodep);
    }

  if (ret != HICN_ERROR_HASHTB_NOMEM)
    {
      if (!is_cs0)
	{
	  ASSERT (ret != HICN_ERROR_NONE);
	  hicn_store_internal_state (b0, hicnb0->name_hash, node_id0,
				     dpo_ctx_id0, vft_id0, hash_entry_id,
				     bucket_id, bucket_is_overflow);

	  (*to_forward)[0] = bi0;
	  *to_forward += 1;
	  *n_to_forward += 1;
	}
      else
	{
	  prep_buffer_for_cs (vm, b0, isv6);
	}
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
  u32 *to_forward = NULL, *header = NULL, n_to_forward = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = (hicn_data_push_next_t) node->cached_next_index;
  rt = vlib_node_get_runtime_data (vm, hicn_data_push_node.index);
  rt->pitcs = &hicn_main.pitcs;

  vec_alloc (to_forward, n_left_from);
  header = to_forward;
  /* Capture time in vpp terms */
  tnow = vlib_time_now (vm);

  while (n_left_from > 0)
    {
      u8 isv6;
      u8 *nameptr;
      u16 namelen;
      hicn_name_t name;
      hicn_header_t *hicn0;
      vlib_buffer_t *b0;
      u32 bi0;
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

      ret0 = hicn_data_parse_pkt (b0, &name, &namelen, &hicn0, &isv6);
      nameptr = (u8 *) (&name);

      if (PREDICT_TRUE (ret0 == HICN_ERROR_NONE))
	{
	  hicn_new_data (vm, rt, b0, &to_forward, &n_to_forward, tnow,
			 nameptr, namelen, isv6);
	  stats.pkts_data_count++;
	}

      /* Maybe trace */
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  hicn_data_push_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->pkt_type = HICN_PKT_TYPE_CONTENT;
	  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  t->next_index = HICN_DATA_PUSH_NEXT_ERROR_DROP;
	}
    }

  to_forward -= n_to_forward;
  next_index = HICN_DATA_PUSH_NEXT_FWD;

  while (n_to_forward > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_to_forward > 0 && n_left_to_next > 0)
	{
	  to_next[0] = to_forward[0];
	  to_forward++;
	  n_to_forward--;
	  to_next++;
	  n_left_to_next--;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vec_free (header);

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
  .next_nodes = {
    [HICN_DATA_PUSH_NEXT_FWD] = "hicn-data-fwd",
    [HICN_DATA_PUSH_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
