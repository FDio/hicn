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

#include "hicn.h"
#include "mapme.h"
#include "mapme_ack.h"
#include "mapme_eventmgr.h"
#include "mgmt.h"
#include "parser.h"
#include "data_fwd.h"
#include "infra.h"
#include "strategy_dpo_manager.h"
#include "error.h"
#include "state.h"

extern hicn_mapme_main_t mapme_main;

/* packet trace format function */
static u8 *hicn_mapme_ack_format_trace (u8 * s, va_list * args);


/* Stats string values */
static char *hicn_mapme_ack_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

/*
 * @brief Process incoming ack messages (Interest Update Ack)
 * @param vm vlib main data structure
 * @param b Control packet (IU)
 * @param face_id Ingress face id
 */
bool
hicn_mapme_process_ack (vlib_main_t * vm, vlib_buffer_t * b,
			dpo_id_t * in_face)
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

  /* if (params.seq == INVALID_SEQ) */
  /*   { */
  /*     DEBUG ("Invalid sequence number found in IU"); */
  /*     return true; */
  /*   } */

  dpo = fib_epm_lookup (&(prefix.name), prefix.len);
  if (!dpo)
    {
      DEBUG ("Ignored ACK for non-existing FIB entry. Ignored.");
      return true;

    }

  /* We are only expecting ACKs for hICN DPOs */
  ASSERT (dpo_is_hicn (dpo));

  hicn_mapme_tfib_t *tfib =
    TFIB (hicn_strategy_dpo_ctx_get (dpo->dpoi_index));

  if (tfib == NULL)
    {
      WARN ("Unable to get strategy ctx.");
      return false;
    }

  fib_seq = tfib->seq;

  /*
   * As we always retransmit IU with the latest seq, we are not interested in
   * ACKs with inferior seq
   */
  if (params.seq < fib_seq)
    {
      DEBUG ("Ignored ACK for low seq");
      return true;
    }

  hicn_mapme_tfib_del (tfib, in_face);

  /*
   * Is the ingress face in TFIB ? if so, remove it, otherwise it might be a
   * duplicate
   */
  retx_t *retx = vlib_process_signal_event_data (vm,
						 hicn_mapme_eventmgr_process_node.
						 index,
						 HICN_MAPME_EVENT_FACE_PH_DEL,
						 1,
						 sizeof (retx_t));
  *retx = (retx_t)
  {
  .prefix = prefix,.dpo = *dpo};
  return true;

ERR_PARSE:
  return false;
}

vlib_node_registration_t hicn_mapme_ack_node;

static uword
hicn_mapme_ack_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame)
{
  hicn_buffer_t *hb;
  hicn_mapme_ack_next_t next_index;
  u32 n_left_from, *from, *to_next;
  n_left_from = frame->n_vectors;

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
	  u32 next0 = HICN_MAPME_ACK_NEXT_ERROR_DROP;
	  u32 sw_if_index0;
	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);

	  vlib_cli_output (vm, "Received IUAck");
	  hb = hicn_get_buffer (b0);
	  hicn_mapme_process_ack (vm, b0, &hb->face_dpo_id);

	  /* Single loop: process 1 packet here */
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicn_mapme_ack_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	    }
	  /* $$$$$ Done processing 1 packet here $$$$$ */

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
//  vlib_node_increment_counter (vm, hicn_mapme_ack_node.index,
//                               HICN_MAPME_ACK_ERROR_SWAPPED, pkts_swapped);
  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn_mapme_ack_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_mapme_ack_trace_t *t = va_arg (*args, hicn_mapme_ack_trace_t *);

  s = format (s, "MAPME_ACK: pkt: %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, t->sw_if_index, t->next_index);
  return (s);
}


/*
 * Node registration for the MAP-Me node processing special interests
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_mapme_ack_node) =
{
  .function = hicn_mapme_ack_node_fn,
  .name = "hicn-mapme-ack",
  .vector_size =  sizeof (u32),
  .runtime_data_bytes = sizeof (hicn_mapme_ack_runtime_t),
  .format_trace = hicn_mapme_ack_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_mapme_ack_error_strings),
  .error_strings = hicn_mapme_ack_error_strings,
  .n_next_nodes = HICN_MAPME_ACK_N_NEXT,
  .next_nodes =
  {
    [HICN_MAPME_ACK_NEXT_ERROR_DROP] = "error-drop",
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
