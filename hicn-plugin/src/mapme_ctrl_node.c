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

/*
 * This node processses MAP-Me control messages.
 */
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/load_balance.h>

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

extern hicn_mapme_main_t mapme_main;

#define MS2NS(x) x * 1000000

/* Functions declarations */

/* packet trace format function */
static u8 *hicn_mapme_ctrl_format_trace (u8 * s, va_list * args);


/* Stats string values */
static char *hicn_mapme_ctrl_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

/*
 * @brief Process incoming control messages (Interest Update)
 * @param vm vlib main data structure
 * @param b Control packet (IU)
 * @param face_id Ingress face id
 *
 * NOTE:
 *  - this function answers locally to the IU interest by replying with a Ack
 *  (Data) packet, unless in case of outdated information, in which we can
 *  consider the interest is dropped, and another IU (aka ICMP error) is sent so
 *  that retransmissions stop.
 */
static_always_inline bool
hicn_mapme_process_ctrl (vlib_main_t * vm, vlib_buffer_t * b,
			 hicn_face_id_t in_face_id)
{
  seq_t fib_seq;
  const dpo_id_t *dpo;
  hicn_prefix_t prefix;
  mapme_params_t params;
  int rc;

  /* Parse incoming message */
  rc =
    hicn_mapme_parse_packet (vlib_buffer_get_current (b), &prefix, &params);
  if (rc < 0)
    goto ERR_PARSE;

  vlib_cli_output (vm, "IU - type:%d seq:%d len:%d", params.type, params.seq,
		   prefix.len);

  /* if (params.seq == INVALID_SEQ) */
  /*   { */
  /*     vlib_log_warn (mapme_main.log_class, */
  /*                 "Invalid sequence number found in IU"); */

  /*     return true; */
  /*   } */

  /* We forge the ACK which we be the packet forwarded by the node */
  hicn_mapme_create_ack (vlib_buffer_get_current (b), &params);

  dpo = fib_epm_lookup (&prefix.name, prefix.len);
  if (!dpo)
    {
#ifdef HICN_MAPME_ALLOW_NONEXISTING_FIB_ENTRY
      /*
       * This might happen for a node hosting a producer which has moved.
       * Destroying the face has led to removing all corresponding FIB
       * entries. In that case, we need to correctly restore the FIB entries.
       */
      DEBUG ("Re-creating FIB entry with next hop on connection")
#error "not implemented"
#else
      //ERROR("Received IU for non-existing FIB entry");
      return false;
#endif /* HICN_MAPME_ALLOW_NONEXISTING_FIB_ENTRY */

    }

#ifdef HICN_MAPME_ALLOW_LOCATORS
  if (!dpo_is_hicn ((dpo)))
    {
      /* We have an IP DPO */
      WARN ("Not implemented yet.");
      return false;
    }
#endif

  /* Process the hICN DPO */
  hicn_mapme_tfib_t *tfib =
    TFIB (hicn_strategy_dpo_ctx_get (dpo->dpoi_index));

  if (tfib == NULL)
    {
      WARN ("Unable to get strategy ctx.");
      return false;
    }

  fib_seq = tfib->seq;

  if (params.seq > fib_seq)
    {
      DEBUG
	("Higher sequence number than FIB %d > %d, updating seq and next hops",
	 params.seq, fib_seq);

      /* This has to be done first to allow processing ack */
      tfib->seq = params.seq;

      // in_face and next_hops are face_id_t

      /* Remove ingress face from TFIB in case it was present */
      hicn_mapme_tfib_del (tfib, in_face_id);

      /* Move next hops to TFIB... but in_face... */
      for (u8 pos = 0; pos < tfib->entry_count; pos++)
	{
          hicn_face_t * face = hicn_dpoi_get_from_idx(tfib->next_hops[pos]);
          hicn_face_t * in_face = hicn_dpoi_get_from_idx(in_face_id);
          if (dpo_is_adj(&face->dpo))
            {
              ip_adjacency_t * adj = adj_get (dpo->dpoi_index);
              if (ip46_address_cmp(&(adj->sub_type.nbr.next_hop), &(in_face->nat_addr))== 0)
                  break;
            }
	  DEBUG
	    ("Adding nexthop to the tfib, dpo index in_face %d, dpo index tfib %d",
	     in_face_id, tfib->next_hops[pos]);
	  hicn_mapme_tfib_add (tfib, tfib->next_hops[pos]);
	}

      hicn_mapme_nh_set (tfib, in_face_id);

      /* We transmit both the prefix and the full dpo (type will be needed to pick the right transmit node */
      retx_t *retx = vlib_process_signal_event_data (vm,
						     hicn_mapme_eventmgr_process_node.
						     index,
						     HICN_MAPME_EVENT_FACE_NH_SET,
						     1,
						     sizeof (retx_t));
      *retx = (retx_t)
        {
         .prefix = prefix,
         .dpo = *dpo
        };

    }
  else if (params.seq == fib_seq)
    {
      DEBUG ("Same sequence number than FIB %d > %d, adding next hop",
	     params.seq, fib_seq);

      /* Remove ingress face from TFIB in case it was present */
      hicn_mapme_tfib_del (tfib, in_face_id);

      /* Add ingress face to next hops */
      hicn_mapme_nh_add (tfib, in_face_id);

      /* Multipath, multihoming, multiple producers or duplicate interest */
      retx_t *retx = vlib_process_signal_event_data (vm,
						     hicn_mapme_eventmgr_process_node.
						     index,
						     HICN_MAPME_EVENT_FACE_NH_ADD,
						     1,
						     sizeof (retx_t));
      *retx = (retx_t)
        {
         .prefix = prefix,
         .dpo = *dpo
        };
    }
  else				// params.seq < fib_seq
    {
      /*
       * face is propagating outdated information, we can just consider it as a
       * prevHops
       */
      hicn_mapme_tfib_add (tfib, in_face_id);

      retx_t *retx = vlib_process_signal_event_data (vm,
						     hicn_mapme_eventmgr_process_node.
						     index,
						     HICN_MAPME_EVENT_FACE_PH_ADD,
						     1,
						     sizeof (retx_t));
      *retx = (retx_t)
        {
         .prefix = prefix,
         .dpo = *dpo
        };
    }

  /* We just raise events, the event_mgr is in charge of forging packet. */

  return true;

//ERR_ACK_CREATE:
ERR_PARSE:
  return false;
}

vlib_node_registration_t hicn_mapme_ctrl_node;

static uword
hicn_mapme_ctrl_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame)
{
  hicn_buffer_t *hb;
  hicn_mapme_ctrl_next_t next_index;
  u32 n_left_from, *from, *to_next;
  n_left_from = frame->n_vectors;
  //hicn_face_id_t in_face;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)	// buffers in the current frame
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

	  /* This determines the next node on which the ack will be sent back */
	  u32 next0 = hicn_mapme_ctrl_get_iface_node (hb->face_id);

	  hicn_mapme_process_ctrl (vm, b0, hb->face_id);

	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = hb->face_id;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  //  vlib_node_increment_counter (vm, hicn_mapme_ctrl_node.index,
  //                               HICN_MAPME_CTRL_ERROR_SWAPPED, pkts_swapped);
  return frame->n_vectors;
}

/* packet trace format function */
static u8 *
hicn_mapme_ctrl_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_mapme_ctrl_trace_t *t = va_arg (*args, hicn_mapme_ctrl_trace_t *);

  s = format (s, "MAPME_CTRL: pkt: %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);
  return (s);
}


/*
 * Node registration for the MAP-Me node processing special interests
 */
/* *INDENT-OFF* */
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
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
