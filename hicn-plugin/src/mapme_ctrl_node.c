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

/*
 * This node processses MAP-Me control messages.
 */
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/load_balance.h>
#include <vlib/log.h>

#include "hicn.h"
#include "mapme.h"
#include "mapme_ctrl.h"
#include "mapme_eventmgr.h"
#include "mgmt.h"
#include "parser.h"
#include "infra.h"
#include "strategy_dpo_manager.h"
#include "strategy_dpo_ctx.h"
#include "error.h"
#include "state.h"
#include "route.h"

extern hicn_mapme_main_t mapme_main;

#define MS2NS(x) x * 1000000

/* Functions declarations */

/* packet trace format function */
static u8 *hicn_mapme_ctrl_format_trace (u8 *s, va_list *args);

/* Stats string values */
static char *hicn_mapme_ctrl_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static_always_inline int
hicn_mapme_nh_set (hicn_mapme_tfib_t *tfib, hicn_face_id_t in_face_id)
{
  hicn_dpo_ctx_t *strategy_ctx = (hicn_dpo_ctx_t *) tfib;
  const fib_prefix_t *prefix =
    fib_entry_get_prefix (strategy_ctx->fib_entry_index);

  int ret = 0;

  if ((tfib->entry_count == 1) && (tfib->next_hops[0] == in_face_id))
    return ret;

  /*
   * Remove all the existing next hops and set the new one
   */
  u32 n_entries = tfib->entry_count;
  for (int i = 0; i < n_entries; i++)
    {
      hicn_face_t *face = hicn_dpoi_get_from_idx (strategy_ctx->next_hops[0]);
      if (dpo_is_adj (&face->dpo))
	{
	  ip_adjacency_t *adj = adj_get (face->dpo.dpoi_index);
	  ip_nh_adj_add_del_helper (prefix->fp_proto, prefix,
				    &adj->sub_type.nbr.next_hop, face->sw_if,
				    0);
	}
      else if (dpo_is_udp_encap (&face->dpo))
	{
	  ip_nh_udp_tunnel_add_del_helper (prefix->fp_proto, prefix,
					   face->dpo.dpoi_index,
					   face->dpo.dpoi_proto, 0);
	}
      else
	{
	  continue;
	}
    }

  ret = HICN_ERROR_MAPME_NEXT_HOP_ADDED;
  hicn_face_t *face = hicn_dpoi_get_from_idx (in_face_id);
  if (dpo_is_udp_encap (&face->dpo))
    {
      ip_nh_udp_tunnel_add_del_helper (prefix->fp_proto, prefix,
				       face->dpo.dpoi_index,
				       face->dpo.dpoi_proto, 1);
    }
  else if (dpo_is_adj (&face->dpo))
    {
      ip_nh_adj_add_del_helper (prefix->fp_proto, prefix, &face->nat_addr,
				face->sw_if, 1);
    }
  else
    {
      ret = HICN_ERROR_MAPME_NEXT_HOP_NOT_ADDED;
    }

  return ret;
}

/**
 * @brief Check whether a face is already included in the FIB nexthops.
 *
 * NOTE: linear scan on a contiguous small array should be the most efficient.
 */
static_always_inline int
hicn_mapme_nh_has (hicn_mapme_tfib_t *tfib, hicn_face_id_t face_id)
{
  for (u8 pos = 0; pos < tfib->entry_count; pos++)
    if (tfib->next_hops[pos] == face_id)
      return 1;
  return 0;
}

/**
 * @brief Add a next hop iif it is not already a next hops
 */
static_always_inline int
hicn_mapme_nh_add (hicn_mapme_tfib_t *tfib, hicn_face_id_t face_id)
{
  if (hicn_mapme_nh_has (tfib, face_id))
    return 0;

  /* Add the next hop in the vrf 0 which will add it to the entry in the hICN
   * vrf */
  hicn_dpo_ctx_t *strategy_ctx = (hicn_dpo_ctx_t *) tfib;
  const fib_prefix_t *prefix =
    fib_entry_get_prefix (strategy_ctx->fib_entry_index);
  hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);
  if (face->dpo.dpoi_type == dpo_type_udp_ip4 ||
      face->dpo.dpoi_type == dpo_type_udp_ip6)
    {
      ip_nh_udp_tunnel_add_del_helper ((fib_protocol_t) face->dpo.dpoi_proto,
				       prefix, face->dpo.dpoi_index,
				       face->dpo.dpoi_proto, 1);
    }
  else
    {
      ip_nh_adj_add_del_helper ((fib_protocol_t) face->dpo.dpoi_proto, prefix,
				&face->nat_addr, face->sw_if, 1);
    }

  return 0;
}

/**
 * @brief Add a route to the fib.
 *
 */
static_always_inline int
hicn_mapme_add_fib_entry (const fib_prefix_t *prefix,
			  hicn_face_id_t in_face_id)
{
  int ret = HICN_ERROR_NONE;
  dpo_proto_t dpo_proto = DPO_PROTO_NONE;

  hicn_face_t *face = hicn_dpoi_get_from_idx (in_face_id);

  if (face->sw_if == ~0)
    {
      // UDP encap case
      if (face->flags & HICN_FACE_FLAGS_UDP4)
	{
	  dpo_proto = DPO_PROTO_IP4;
	}
      else if (face->flags & HICN_FACE_FLAGS_UDP6)
	{
	  dpo_proto = DPO_PROTO_IP6;
	}
      else
	{
	  // Invalid
	  ret = HICN_ERROR_FACE_NOT_VALID;
	  goto end;
	}

      ret = ip_nh_udp_tunnel_add_del_helper (
	prefix->fp_proto, prefix, face->dpo.dpoi_index, dpo_proto, 1);
    }
  else
    {
      ret = ip_nh_adj_add_del_helper (prefix->fp_proto, prefix,
				      &face->nat_addr, face->sw_if, 1);
    }

  // Now let's trigger the sync the main table with the hicn table
  hicn_face_id_t *vec_faces = NULL;
  ret = hicn_route_enable (prefix, &vec_faces);

  ASSERT (vec_faces[0] == in_face_id);

  if (vec_faces[0] != in_face_id)
    {
      clib_warning ("Created new faces. New face: %d, In face: %d",
		    vec_faces[0], in_face_id);
    }

end:
  // We are done!
  return ret;
}

/**
 * Convert hicn prefix to fib prefix
 */
static_always_inline void
hicn_prefix_to_fib_prefix (const hicn_prefix_t *prefix_in,
			   fib_prefix_t *prefix_out)
{
  clib_memcpy (&prefix_out->fp_addr, &prefix_in->name.as_ip46,
	       sizeof (prefix_out->fp_addr));
  prefix_out->fp_len = (u16) prefix_in->len;
  prefix_out->fp_proto = ip46_address_is_ip4 (&prefix_out->fp_addr) ?
			   FIB_PROTOCOL_IP4 :
			   FIB_PROTOCOL_IP6;
}

/*
 * @brief Process incoming control messages (Interest Update)
 * @param vm vlib main data structure
 * @param b Control packet (IU)
 * @param face_id Ingress face id
 *
 * NOTE:
 *  - this function answers locally to the IU interest by replying with a Ack
 *  (Data) packet, unless in case of outdated information, in which we can
 *  consider the interest is dropped, and another IU (aka ICMP error) is sent
 * so that retransmissions stop.
 */
static_always_inline bool
hicn_mapme_process_ctrl (vlib_main_t *vm, vlib_buffer_t *b,
			 hicn_face_id_t in_face_id, hicn_prefix_t *prefix,
			 u32 *seq, hicn_mapme_type_t *type)
{
  seq_t fib_seq;
  const dpo_id_t *dpo, *dpo_less_specific;
  fib_prefix_t fib_prefix;
  mapme_params_t params;
  hicn_mapme_tfib_t *tfib;
  int rc;

  /* Parse incoming message */
  rc = hicn_mapme_parse_packet (vlib_buffer_get_current (b), prefix, &params);
  if (rc < 0)
    goto ERR_PARSE;

  *seq = params.seq;
  *type = params.type;

  HICN_DEBUG ("IU - type:%d seq:%d prefix:%U len:%d", params.type, params.seq,
	      format_ip46_address, &prefix->name, IP46_TYPE_ANY, prefix->len);

  /* if (params.seq == INVALID_SEQ) */
  /*   { */
  /*     vlib_log_warn (mapme_main.log_class, */
  /*                 "Invalid sequence number found in IU"); */

  /*     return true; */
  /*   } */

  /* We forge the ACK which we be the packet forwarded by the node */
  hicn_mapme_create_ack (vlib_buffer_get_current (b), &params);

  dpo = fib_lookup (&prefix->name.as_ip46, prefix->len,
		    HICN_MAPME_FIB_LOOKUP_TYPE_EPM);
  if (!dpo)
    {
#ifdef HICN_MAPME_ALLOW_NONEXISTING_FIB_ENTRY
      hicn_mapme_tfib_t *tfib_less_specific;

      /*
       * This might happen for a node hosting a producer which has moved.
       * Destroying the face has led to removing all corresponding FIB
       * entries. In that case, we need to correctly restore the FIB entries.
       */

      // Perform LPM to get the next hop
      hicn_prefix_to_fib_prefix (prefix, &fib_prefix);

      HICN_DEBUG ("Re-creating FIB entry with next hop on connection");
      rc = hicn_mapme_add_fib_entry (&fib_prefix, in_face_id);

      ASSERT (rc == HICN_ERROR_NONE);

      dpo = fib_lookup (&prefix->name.as_ip46, prefix->len,
			HICN_MAPME_FIB_LOOKUP_TYPE_EPM);

      // As the EPM failed (but we received the IU), it means we have another
      // prefix that is either more or less specific to which forward
      // the IU. For the moment we do not update the NHs for this prefix, but
      // we just forward the IU.

      // Get the dpo ctx of the least specific route for this prefix
      dpo_less_specific = fib_lookup (&prefix->name.as_ip46, 64,
				      HICN_MAPME_FIB_LOOKUP_TYPE_LESSPM);

      u32 hicn_dpo_ctx_index = dpo->dpoi_index;
      u32 hicn_dpo_ctx_index_less_specific_route =
	dpo_less_specific->dpoi_index;

      tfib_less_specific = TFIB (
	hicn_strategy_dpo_ctx_get (hicn_dpo_ctx_index_less_specific_route));
      tfib = TFIB (hicn_strategy_dpo_ctx_get (hicn_dpo_ctx_index));

      for (u8 pos = 0; pos < tfib_less_specific->entry_count; pos++)
	{
	  //   if (tfib_less_specific->next_hops[pos] == in_face_id)
	  //     continue;
	  HICN_DEBUG (
	    "Adding nexthop to the tfib, dpo index in_face %d, dpo index "
	    "tfib %d",
	    in_face_id, tfib_less_specific->next_hops[pos]);
	  hicn_mapme_tfib_add (tfib, tfib_less_specific->next_hops[pos]);
	}

      // Update sequence number
      tfib->seq = params.seq;

      retx_t *retx = vlib_process_signal_event_data (
	vm, hicn_mapme_eventmgr_process_node.index,
	HICN_MAPME_EVENT_FACE_NH_SET, 1, sizeof (retx_t));
      *retx = (retx_t){ .prefix = *prefix,
			.dpo = {
			  .dpoi_index = hicn_dpo_ctx_index,
			  .dpoi_type = DPO_FIRST,
			} };

      return true;
#else
      HICN_ERROR ("Received IU for non-existing FIB entry");
      return false;
#endif /* HICN_MAPME_ALLOW_NONEXISTING_FIB_ENTRY */
    }

#ifdef HICN_MAPME_ALLOW_LOCATORS
  if (!dpo_is_hicn ((dpo)))
    {
      /* We have an IP DPO */
      HICN_ERROR ("Not implemented yet.");
      return false;
    }
#endif

  /* Process the hICN DPO */
  tfib = TFIB (hicn_strategy_dpo_ctx_get (dpo->dpoi_index));

  if (tfib == NULL)
    {
      HICN_ERROR ("Unable to get strategy ctx.");
      return false;
    }

  fib_seq = tfib->seq;

  if (params.seq > fib_seq)
    {
      HICN_DEBUG (
	"Higher sequence number than FIB %d > %d, updating seq and next hops",
	params.seq, fib_seq);

      /* This has to be done first to allow processing ack */
      tfib->seq = params.seq;

      // in_face and next_hops are face_id_t

      /* Remove ingress face from TFIB in case it was present */
      hicn_mapme_tfib_del (tfib, in_face_id);

      HICN_DEBUG ("Locks on face %d: %d", in_face_id,
		  hicn_dpoi_get_from_idx (in_face_id)->locks);

      /* Move next hops to TFIB... but in_face... */
      for (u8 pos = 0; pos < tfib->entry_count; pos++)
	{
	  if (tfib->next_hops[pos] == in_face_id)
	    continue;
	  HICN_DEBUG (
	    "Adding nexthop to the tfib, dpo index in_face %d, dpo index "
	    "tfib %d",
	    in_face_id, tfib->next_hops[pos]);
	  hicn_mapme_tfib_add (tfib, tfib->next_hops[pos]);
	}

      int ret = hicn_mapme_nh_set (tfib, in_face_id);
      HICN_DEBUG ("Locks on face %d: %d", in_face_id,
		  hicn_dpoi_get_from_idx (in_face_id)->locks);
      if (ret == HICN_ERROR_MAPME_NEXT_HOP_ADDED &&
	  hicn_get_buffer (b)->flags & HICN_BUFFER_FLAGS_NEW_FACE)
	{
	  hicn_face_unlock_with_id (in_face_id);
	}

      /* We transmit both the prefix and the full dpo (type will be needed to
       * pick the right transmit node */
      retx_t *retx = vlib_process_signal_event_data (
	vm, hicn_mapme_eventmgr_process_node.index,
	HICN_MAPME_EVENT_FACE_NH_SET, 1, sizeof (retx_t));
      *retx = (retx_t){ .prefix = *prefix, .dpo = *dpo };
    }
  else if (params.seq == fib_seq)
    {
      HICN_DEBUG ("Same sequence number than FIB %d > %d, adding next hop",
		  params.seq, fib_seq);

      /**
       * Add nh BEFORE removing the face from the tfib, as if the last lock is
       * held by the tfib, deleting it first would also delete the face,
       * resulting in a undefined behavior after (Debug mode -> SIGABRT,
       * Release Mode -> Corrupted memory / SIGSEGV).
       **/

      /* Add ingress face to next hops */
      hicn_mapme_nh_add (tfib, in_face_id);

      /* Remove ingress face from TFIB in case it was present */
      hicn_mapme_tfib_del (tfib, in_face_id);

      /* Multipath, multihoming, multiple producers or duplicate interest */
      retx_t *retx = vlib_process_signal_event_data (
	vm, hicn_mapme_eventmgr_process_node.index,
	HICN_MAPME_EVENT_FACE_NH_ADD, 1, sizeof (retx_t));
      *retx = (retx_t){ .prefix = *prefix, .dpo = *dpo };
    }
  else // params.seq < fib_seq
    {
      /*
       * face is propagating outdated information, we can just consider it as a
       * prevHops, unless it is the current nexthop.
       */
      if (hicn_mapme_nh_has (tfib, in_face_id))
	{
	  HICN_DEBUG ("Ignored seq %d < fib_seq %d from current nexthop",
		      params.seq, fib_seq);
	  return true;
	}
      HICN_DEBUG ("Received seq %d < fib_seq %d, sending backwards",
		  params.seq, fib_seq);

      hicn_mapme_tfib_add (tfib, in_face_id);

      retx_t *retx = vlib_process_signal_event_data (
	vm, hicn_mapme_eventmgr_process_node.index,
	HICN_MAPME_EVENT_FACE_PH_ADD, 1, sizeof (retx_t));
      *retx = (retx_t){ .prefix = *prefix, .dpo = *dpo };
    }

  /* We just raise events, the event_mgr is in charge of forging packet. */

  return true;

// ERR_ACK_CREATE:
ERR_PARSE:
  return false;
}

vlib_node_registration_t hicn_mapme_ctrl_node;

static uword
hicn_mapme_ctrl_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame)
{
  hicn_buffer_t *hb;
  hicn_mapme_ctrl_next_t next_index;
  u32 n_left_from, *from, *to_next;
  n_left_from = frame->n_vectors;
  // hicn_face_id_t in_face;
  hicn_prefix_t prefix;
  u32 seq;
  hicn_mapme_type_t type;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0) // buffers in the current frame
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);
	  hb = hicn_get_buffer (b0);

	  /* This determines the next node on which the ack will be sent back
	   */
	  u32 next0 = HICN_MAPME_CTRL_NEXT_IP6_OUTPUT;

	  hicn_mapme_process_ctrl (vm, b0, hb->face_id, &prefix, &seq, &type);

	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = hb->face_id;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_mapme_ctrl_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->prefix = prefix;
	      t->next_index = next0;
	      t->seq = seq;
	      t->type = type;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  //  vlib_node_increment_counter (vm, hicn_mapme_ctrl_node.index,
  //                               HICN_MAPME_CTRL_ERROR_SWAPPED,
  //                               pkts_swapped);
  return frame->n_vectors;
}

/* packet trace format function */
static u8 *
hicn_mapme_ctrl_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_mapme_ctrl_trace_t *t = va_arg (*args, hicn_mapme_ctrl_trace_t *);

  s = format (s, "MAPME_CTRL: prefix: %U/%d, next_index %u, seq %u, type %u",
	      format_ip46_address, &t->prefix.name, IP46_TYPE_ANY,
	      t->prefix.len, t->next_index, t->seq, t->type);
  return (s);
}

/*
 * Node registration for the MAP-Me node processing special interests
 */
VLIB_REGISTER_NODE (hicn_mapme_ctrl_node) =
{
  .function = hicn_mapme_ctrl_node_fn,
  .name = "hicn-mapme-ctrl",
  .vector_size =  sizeof (u32),
  .runtime_data_bytes = sizeof (hicn_mapme_ctrl_runtime_t),
  .format_trace = hicn_mapme_ctrl_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_mapme_ctrl_error_strings),
  .error_strings = hicn_mapme_ctrl_error_strings,
  .n_next_nodes = HICN_MAPME_CTRL_N_NEXT,
  .next_nodes =
  {
    /*
     * Control packets are not forwarded by this node, but sent by the Event
     * Manager. This node is only responsible for sending ACK back,
     * Acks are like data packets are output on iface's
     */
    [HICN_MAPME_CTRL_NEXT_IP4_OUTPUT]   = "hicn4-iface-output",
    [HICN_MAPME_CTRL_NEXT_IP6_OUTPUT]   = "hicn6-iface-output",
    [HICN_MAPME_CTRL_NEXT_ERROR_DROP]   = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
