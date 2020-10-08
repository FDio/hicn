/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/mpls/packet.h>

#include "hicn_handoff.h"
#include "infra.h"
#include "mgmt.h"

static char *hicn_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static u8 *
format_hicn_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_handoff_trace_t *t = va_arg (*args, hicn_handoff_trace_t *);

  s =
    format (s, "worker-handoff: sw_if_index %d, next_worker %d, buffer 0x%x",
	    t->sw_if_index, t->next_worker_index, t->buffer_index);
  return s;
}

VLIB_NODE_FN (hicn_handoff_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  hicn_main_t *sm = get_hicn_main();
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      u32 sw_if_index0;
//       u32 hash;
//       u64 hash_key;
//       per_inteface_handoff_data_t *ihd0;
//       u32 index0;
      
      sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];

      ti[0] = vlib_get_thread_index();

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  hicn_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_worker_index = ti[0];
	  t->buffer_index = vlib_get_buffer_index (vm, b[0]);
	}

      /* next */
      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, hm->frame_queue_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 HICNFWD_ERROR_WORKER_HANDOFF_CONGESTION,
				 frame->n_vectors - n_enq);
  
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_handoff_node) = {
  .name = "hicn-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_hicn_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn_handoff_error_strings),
  .error_strings = hicn_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

static uword
hicn_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_frame_t * frame)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_input_node) = {
  .function = hicn_input_fn,
  .name = "hicn-input",
  .runtime_data_bytes = sizeof (vnet_device_input_runtime_t),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_next_nodes = VNET_DEVICE_INPUT_N_NEXT_NODES,
  .next_nodes = VNET_DEVICE_INPUT_NEXT_NODES,
};

VNET_FEATURE_ARC_INIT (device_input, static) =
{
  .arc_name  = "hicn-input",
  .start_nodes = VNET_FEATURES ("device-input"),
  .last_in_arc = "ethernet-input",
  .arc_index_ptr = &feature_main.device_input_feature_arc_index,
};

VNET_FEATURE_INIT (hicn_handoff, static) = {
  .arc_name = "device-input",
  .node_name = "worker-handoff",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
