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

#include <vnet/dpo/dpo.h>

#include "data_fwd.h"
#include "mgmt.h"
#include "parser.h"
#include "infra.h"
#include "strategy.h"
#include "strategy_dpo_manager.h"
#include "state.h"
#include "error.h"

/* Stats string values */
static char *hicn_data_fwd_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

/* Declarations */
always_inline void
drop_packet (vlib_main_t * vm, u32 bi0,
	     u32 * n_left_to_next, u32 * next0, u32 ** to_next,
	     u32 * next_index, vlib_node_runtime_t * node);

always_inline void
push_in_cache (vlib_main_t * vm, u32 bi0,
	       u32 * n_left_to_next, u32 * next0, u32 ** to_next,
	       u32 * next_index, vlib_node_runtime_t * node);

always_inline int
hicn_satisfy_faces (vlib_main_t * vm, u32 b0,
		    hicn_pcs_entry_t * pitp, u32 * n_left_to_next,
		    u32 ** to_next, u32 * next_index,
		    vlib_node_runtime_t * node, u8 isv6,
		    vl_api_hicn_api_node_stats_get_reply_t * stats);

always_inline void
clone_data_to_cs (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		  hicn_pcs_entry_t * pitp, hicn_header_t * hicn0, f64 tnow,
		  hicn_hash_node_t * nodep, vlib_buffer_t * b0,
		  hicn_hash_entry_t * hash_entry, u64 name_hash,
		  hicn_buffer_t * hicnb, const hicn_dpo_vft_t * dpo_vft,
		  dpo_id_t * hicn_dpo_id, hicn_lifetime_t dmsg_lifetime);


/* packet trace format function */
always_inline u8 *hicn_data_fwd_format_trace (u8 * s, va_list * args);

vlib_node_registration_t hicn_data_fwd_node;

/*
 * ICN forwarder node for interests: handling of Data delivered based on ACL.
 * - 1 packet at a time - ipv4/tcp ipv6/tcp
 */
static uword
hicn_data_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		   vlib_frame_t * frame)
{

  u32 n_left_from, *from, *to_next;
  hicn_data_fwd_next_t next_index;
  hicn_pit_cs_t *pitcs = &hicn_main.pitcs;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  f64 tnow;
  u32 data_received = 1;

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
	  u32 next0 = HICN_DATA_FWD_NEXT_ERROR_DROP;
	  hicn_name_t name;
	  hicn_header_t *hicn0;
	  hicn_buffer_t *hicnb0;
	  hicn_hash_node_t *node0;
	  const hicn_strategy_vft_t *strategy_vft0;
	  const hicn_dpo_vft_t *dpo_vft0;
	  u8 dpo_ctx_id0;
	  hicn_pcs_entry_t *pitp;
	  hicn_hash_entry_t *hash_entry0;
	  int ret = HICN_ERROR_NONE;

	  /* Prefetch for next iteration. */
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, 2 * CLIB_CACHE_LINE_BYTES, STORE);
	      CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, STORE);
	    }
	  /* Dequeue a packet buffer */
	  /*
	   * Do not copy the index in the next buffer, we'll do
	   * it later. The packet might be cloned, so the buffer to move
	   * to next must be the cloned one
	   */
	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Get hicn buffer and state */
	  hicnb0 = hicn_get_buffer (b0);
	  hicn_get_internal_state (hicnb0, pitcs, &node0, &strategy_vft0,
				   &dpo_vft0, &dpo_ctx_id0, &hash_entry0);

	  ret = hicn_data_parse_pkt (b0, &name, &namelen, &hicn0, &isv6);
	  pitp = hicn_pit_get_data (node0);
	  nameptr = (u8 *) (&name);

	  if (PREDICT_FALSE
	      (ret != HICN_ERROR_NONE
	       || !hicn_node_compare (nameptr, namelen, node0)
	       || (hash_entry0->he_flags & HICN_HASH_ENTRY_FLAG_CS_ENTRY)))
	    {
	      /*
	       * Remove the lock acquired from
	       * data_pcslookup node
	       */
	      dpo_id_t hicn_dpo_id0 = { dpo_vft0->hicn_dpo_get_type (), 0, 0,
		dpo_ctx_id0
	      };
	      hicn_pcs_remove_lock (pitcs, &pitp, &node0, vm,
				    hash_entry0, dpo_vft0, &hicn_dpo_id0);

	      drop_packet (vm, bi0, &n_left_to_next, &next0, &to_next,
			   &next_index, node);

	      goto end_processing;
	    }
	  /*
	   * Check if the hit is instead a collision in the
	   * hash table. Unlikely to happen.
	   */
	  /*
	   * there is no guarantee that the type of entry has
	   * not changed from the lookup.
	   */

	  if (tnow > pitp->shared.expire_time
	      || (hash_entry0->he_flags & HICN_HASH_ENTRY_FLAG_DELETED))
	    {
	      dpo_id_t hicn_dpo_id0 =
		{ dpo_vft0->hicn_dpo_get_type (), 0, 0, dpo_ctx_id0 };
	      hicn_pcs_delete (pitcs, &pitp, &node0, vm, hash_entry0,
			       dpo_vft0, &hicn_dpo_id0);

#if HICN_FEATURE_CS
	      if (hicnb0->flags & HICN_BUFFER_FLAGS_FACE_IS_APP)
		{
		  push_in_cache (vm, bi0, &n_left_to_next, &next0, &to_next,
				 &next_index, node);
		}
	      else
		{
		  drop_packet (vm, bi0, &n_left_to_next, &next0, &to_next,
			       &next_index, node);
		}
#else
              drop_packet (vm, bi0, &n_left_to_next, &next0, &to_next,
                           &next_index, node);
#endif
	      stats.pit_expired_count++;

	      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
				 (b0->flags & VLIB_BUFFER_IS_TRACED)))
		{
		  hicn_data_fwd_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->pkt_type = HICN_PKT_TYPE_CONTENT;
		  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
		  t->next_index = next0;
		  clib_memcpy (t->packet_data,
			       vlib_buffer_get_current (b0),
			       sizeof (t->packet_data));
		}
	    }
	  else
	    {
	      ASSERT ((hash_entry0->he_flags & HICN_HASH_ENTRY_FLAG_DELETED)
		      == 0);

	      data_received++;
	      /*
	       * We do not check if the data is coming from
	       * the outgoing interest face.
	       */

	      /* Prepare the buffer for the cloning */
	      ret = hicn_satisfy_faces (vm, bi0, pitp, &n_left_to_next,
					&to_next, &next_index, node,
					isv6, &stats);

	      dpo_id_t hicn_dpo_id0 = { dpo_vft0->hicn_dpo_get_type (), 0, 0,
		dpo_ctx_id0
	      };

	      if (PREDICT_FALSE (ret != HICN_ERROR_NONE))
		{
		  hicn_pcs_pit_delete (pitcs, &pitp, &node0, vm,
				       hash_entry0, dpo_vft0, &hicn_dpo_id0);
		  continue;
		}
	      /*
	       * Call the strategy callback since the
	       * interest has been satisfied
	       */
	      strategy_vft0->hicn_receive_data (dpo_ctx_id0,
						pitp->u.pit.pe_txnh);

#if HICN_FEATURE_CS
	      hicn_lifetime_t dmsg_lifetime;

	      hicn_type_t type = hicnb0->type;
	      hicn_ops_vft[type.l1]->get_lifetime (type, &hicn0->protocol,
						   &dmsg_lifetime);

	      if (dmsg_lifetime)
		{
		  /*
		   * Clone data packet in the content store and
		   * convert the PIT entry into a CS entry
		   */
		  clone_data_to_cs (vm, pitcs, pitp, hicn0, tnow, node0,
				    b0, hash_entry0, hicnb0->name_hash,
				    hicnb0, dpo_vft0, &hicn_dpo_id0,
				    dmsg_lifetime);

		  hicn_pcs_remove_lock (pitcs, &pitp, &node0, vm,
					hash_entry0, NULL, NULL);
		}
	      else
		{
		  /*
		   * If the packet is copied and not cloned, we need to free the vlib_buffer
		   */
		  if (hicnb0->flags & HICN_BUFFER_FLAGS_PKT_LESS_TWO_CL)
		    {
		      vlib_buffer_free_one (vm, bi0);
		    }
		  else
		    {
		      /*
		       * Remove one reference as the buffer is no
		       * longer in any frame. The vlib_buffer will be freed when
		       * all its cloned vlib_buffer will be freed.
		       */
		      b0->ref_count--;
		    }

		  /* Delete the PIT entry */
		  hicn_pcs_pit_delete (pitcs, &pitp, &node0, vm,
				       hash_entry0, dpo_vft0, &hicn_dpo_id0);
		}
#else
	      ASSERT (pitp == hicn_pit_get_data (node0));
	      /*
	       * If the packet is copied and not cloned, we need to free the vlib_buffer
	       */
	      if (hicnb0->flags & HICN_BUFFER_FLAGS_PKT_LESS_TWO_CL)
		{
		  vlib_buffer_free_one (vm, bi0);
		}
	      else
		{
		  /*
		   * Remove one reference as the buffer is no
		   * longer in any frame. The vlib_buffer will be freed when
		   * all its cloned vlib_buffer will be freed.
		   */
		  b0->ref_count--;
		}

	      /* Delete the PIT entry */
	      hicn_pcs_pit_delete (pitcs, &pitp, &node0, vm,
				   hash_entry0, dpo_vft0, &hicn_dpo_id0);
#endif
	    }
	end_processing:

	  /* Incr packet counter */
	  stats.pkts_processed += 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  u32 pit_int_count = hicn_pit_get_int_count (pitcs);
  u32 pit_cs_count = hicn_pit_get_cs_count (pitcs);

  vlib_node_increment_counter (vm, hicn_data_fwd_node.index,
			       HICNFWD_ERROR_DATAS, stats.pkts_data_count);


  update_node_counter (vm, hicn_data_fwd_node.index,
		       HICNFWD_ERROR_INT_COUNT, pit_int_count);
  update_node_counter (vm, hicn_data_fwd_node.index,
		       HICNFWD_ERROR_CS_COUNT, pit_cs_count);
  update_node_counter (vm, hicn_data_fwd_node.index,
		       HICNFWD_ERROR_INTEREST_AGG_ENTRY,
		       stats.pkts_data_count / data_received);

  return (frame->n_vectors);
}

always_inline void
drop_packet (vlib_main_t * vm, u32 bi0,
	     u32 * n_left_to_next, u32 * next0, u32 ** to_next,
	     u32 * next_index, vlib_node_runtime_t * node)
{
  *next0 = HICN_DATA_FWD_NEXT_ERROR_DROP;

  (*to_next)[0] = bi0;
  *to_next += 1;
  *n_left_to_next -= 1;

  vlib_validate_buffer_enqueue_x1 (vm, node, *next_index,
				   *to_next, *n_left_to_next, bi0, *next0);
}

always_inline void
push_in_cache (vlib_main_t * vm, u32 bi0,
	       u32 * n_left_to_next, u32 * next0, u32 ** to_next,
	       u32 * next_index, vlib_node_runtime_t * node)
{
  *next0 = HICN_DATA_FWD_NEXT_PUSH;

  (*to_next)[0] = bi0;
  *to_next += 1;
  *n_left_to_next -= 1;

  vlib_validate_buffer_enqueue_x1 (vm, node, *next_index,
				   *to_next, *n_left_to_next, bi0, *next0);
}

always_inline int
hicn_satisfy_faces (vlib_main_t * vm, u32 bi0,
		    hicn_pcs_entry_t * pitp, u32 * n_left_to_next,
		    u32 ** to_next, u32 * next_index,
		    vlib_node_runtime_t * node, u8 isv6,
		    vl_api_hicn_api_node_stats_get_reply_t * stats)
{
  int found = 0;
  int ret = HICN_ERROR_NONE;
  u32 *clones = NULL, *header = NULL;
  u32 n_left_from = 0;
  u32 next0 = HICN_DATA_FWD_NEXT_ERROR_DROP, next1 =
    HICN_DATA_FWD_NEXT_ERROR_DROP;
  word buffer_advance = CLIB_CACHE_LINE_BYTES * 2;

  /*
   * We have a hard limit on the number of vlib_buffer that we can
   * chain (no more than 256)
   */
  /*
   * The first group of vlib_buffer can be directly cloned from b0. We
   * need to be careful to clone it only 254 times as the buffer
   * already has n_add_reds=1.
   */
  vec_alloc (clones, pitp->u.pit.faces.n_faces);
  header = clones;

  /* Clone bi0 */
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

  hicn_buffer_t *hicnb = hicn_get_buffer (b0);

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
      /* Add one reference to maintain the buffer in the CS.
       * b0->ref_count == 0 has two meaning: it has 1 buffer or no buffer chained to it.
       * vlib_buffer_clone2 add a number of reference equalt to pitp->u.pit.faces.n_faces - 1
       * as vlib_buffer_clone does. So after all the packet are forwarded the buffer stored in
       * the CS will have ref_count == 0;
       */
      b0->ref_count++;
    }

  found = n_left_from =
    vlib_buffer_clone2 (vm, bi0, clones, pitp->u.pit.faces.n_faces,
			buffer_advance);

  ASSERT (n_left_from == pitp->u.pit.faces.n_faces);

  /* Index to iterate over the faces */
  int i = 0;

  while (n_left_from > 0)
    {

      //Dual loop, X2
      while (n_left_from >= 4 && *n_left_to_next >= 2)
	{
	  vlib_buffer_t *h0, *h1;
	  u32 hi0, hi1;
	  hicn_face_id_t face0, face1;

	  /* Prefetch for next iteration. */
	  {
	    vlib_buffer_t *h2, *h3;
	    h2 = vlib_get_buffer (vm, clones[2]);
	    h3 = vlib_get_buffer (vm, clones[3]);
	    CLIB_PREFETCH (h2, 2 * CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (h3, 2 * CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  face0 = hicn_face_db_get_dpo_face (i++, &pitp->u.pit.faces);
	  face1 = hicn_face_db_get_dpo_face (i++, &pitp->u.pit.faces);

	  h0 = vlib_get_buffer (vm, clones[0]);
	  h1 = vlib_get_buffer (vm, clones[1]);

	  (*to_next)[0] = hi0 = clones[0];
	  (*to_next)[1] = hi1 = clones[1];
	  *to_next += 2;
	  *n_left_to_next -= 2;
	  n_left_from -= 2;
	  clones += 2;

	  next0 = isv6 ? HICN_DATA_FWD_NEXT_IFACE6_OUT :
            HICN_DATA_FWD_NEXT_IFACE4_OUT;
	  next1 = isv6 ? HICN_DATA_FWD_NEXT_IFACE6_OUT :
            HICN_DATA_FWD_NEXT_IFACE4_OUT;

          vnet_buffer (h0)->ip.adj_index[VLIB_TX] = face0;
	  vnet_buffer (h1)->ip.adj_index[VLIB_TX] = face1;

	  stats->pkts_data_count += 2;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (h0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_data_fwd_trace_t *t =
		vlib_add_trace (vm, node, h0, sizeof (*t));
	      t->pkt_type = HICN_PKT_TYPE_CONTENT;
	      t->sw_if_index = vnet_buffer (h0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      clib_memcpy (t->packet_data,
			   vlib_buffer_get_current (h0),
			   sizeof (t->packet_data));
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (h1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_data_fwd_trace_t *t =
		vlib_add_trace (vm, node, h1, sizeof (*t));
	      t->pkt_type = HICN_PKT_TYPE_CONTENT;
	      t->sw_if_index = vnet_buffer (h1)->sw_if_index[VLIB_RX];
	      t->next_index = next1;
	      clib_memcpy (t->packet_data,
			   vlib_buffer_get_current (h1),
			   sizeof (t->packet_data));
	    }
	  vlib_validate_buffer_enqueue_x2 (vm, node, *next_index,
					   (*to_next), *n_left_to_next,
					   hi0, hi1, next0, next1);
	}


      while (n_left_from > 0 && *n_left_to_next > 0)
	{
	  vlib_buffer_t *h0;
	  u32 hi0;
	  hicn_face_id_t face0;

	  face0 = hicn_face_db_get_dpo_face (i++, &pitp->u.pit.faces);

	  h0 = vlib_get_buffer (vm, clones[0]);

	  (*to_next)[0] = hi0 = clones[0];
	  *to_next += 1;
	  *n_left_to_next -= 1;
	  n_left_from -= 1;
	  clones += 1;

	  next0 = isv6 ? HICN_DATA_FWD_NEXT_IFACE6_OUT :
            HICN_DATA_FWD_NEXT_IFACE4_OUT;
	  vnet_buffer (h0)->ip.adj_index[VLIB_TX] = face0;

	  stats->pkts_data_count++;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (h0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_data_fwd_trace_t *t =
		vlib_add_trace (vm, node, h0, sizeof (*t));
	      t->pkt_type = HICN_PKT_TYPE_CONTENT;
	      t->sw_if_index = vnet_buffer (h0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      clib_memcpy (t->packet_data,
			   vlib_buffer_get_current (h0),
			   sizeof (t->packet_data));
	    }
	  /*
	   * Verify speculative enqueue, maybe switch current
	   * next frame
	   */
	  /*
	   * Fix in case of a wrong speculation. Needed to
	   * clone the data in the right frame
	   */
	  vlib_validate_buffer_enqueue_x1 (vm, node, *next_index,
					   *to_next, *n_left_to_next,
					   hi0, next0);

	}

      /* Ensure that there is space for the next clone (if any) */
      if (PREDICT_FALSE (*n_left_to_next == 0))
	{
	  vlib_put_next_frame (vm, node, *next_index, *n_left_to_next);

	  vlib_get_next_frame (vm, node, *next_index, *to_next,
			       *n_left_to_next);
	}
    }

  vec_free (header);

  if (PREDICT_FALSE (!found))
    {
      ASSERT (0);
      drop_packet (vm, bi0, n_left_to_next, &next0, to_next, next_index,
		   node);
      ret = HICN_ERROR_FACE_NOT_FOUND;
    }
  return ret;
}

always_inline void
clone_data_to_cs (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		  hicn_pcs_entry_t * pitp, hicn_header_t * hicn0, f64 tnow,
		  hicn_hash_node_t * nodep, vlib_buffer_t * b0,
		  hicn_hash_entry_t * hash_entry, u64 name_hash,
		  hicn_buffer_t * hicnb, const hicn_dpo_vft_t * dpo_vft,
		  dpo_id_t * hicn_dpo_id, hicn_lifetime_t dmsg_lifetime)
{
  /*
   * At this point we think we're safe to proceed. Store the CS buf in
   * the PIT/CS hashtable entry
   */

  /*
   * Start turning the PIT into a CS. Note that we may be stepping on
   * the PIT part of the union as we update the CS part, so don't
   * expect the PIT part to be valid after this point.
   */
  hicn_buffer_t *hicnb0 = hicn_get_buffer (b0);
  hicn_pit_to_cs (vm, pitcs, pitp, hash_entry, nodep, dpo_vft, hicn_dpo_id,
		  hicnb->face_id,
		  hicnb0->flags & HICN_BUFFER_FLAGS_FACE_IS_APP);

  pitp->shared.create_time = tnow;

  if (dmsg_lifetime < HICN_PARAM_CS_LIFETIME_MIN
      || dmsg_lifetime > HICN_PARAM_CS_LIFETIME_MAX)
    {
      dmsg_lifetime = HICN_PARAM_CS_LIFETIME_DFLT;
    }
  pitp->shared.expire_time = hicn_pcs_get_exp_time (tnow, dmsg_lifetime);

  /* Store the original packet buffer in the CS node */
  pitp->u.cs.cs_pkt_buf = vlib_get_buffer_index (vm, b0);
}

/* packet trace format function */
always_inline u8 *
hicn_data_fwd_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_data_fwd_trace_t *t = va_arg (*args, hicn_data_fwd_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "DATAFWD: pkt: %d, sw_if_index %d, next index %d\n",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);

  s = format (s, "%U%U", format_white_space, indent,
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the data forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn_data_fwd_node) =
{
  .function = hicn_data_node_fn,
  .name = "hicn-data-fwd",
  .vector_size = sizeof(u32),
  .format_trace = hicn_data_fwd_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn_data_fwd_error_strings),
  .error_strings = hicn_data_fwd_error_strings,
  .n_next_nodes = HICN_DATA_FWD_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [HICN_DATA_FWD_NEXT_V4_LOOKUP] = "ip4-lookup",
    [HICN_DATA_FWD_NEXT_V6_LOOKUP] = "ip6-lookup",
    [HICN_DATA_FWD_NEXT_PUSH] = "hicn-data-push",
    [HICN_DATA_FWD_NEXT_IFACE4_OUT] = "hicn4-iface-output",
    [HICN_DATA_FWD_NEXT_IFACE6_OUT] = "hicn6-iface-output",
    [HICN_DATA_FWD_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
