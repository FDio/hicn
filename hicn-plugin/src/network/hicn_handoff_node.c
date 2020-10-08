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

hicn_handoff_main_t hicn_handoff_main;

extern vlib_node_registration_t hicn4_iface_input_node;
extern vlib_node_registration_t hicn6_iface_input_node;
extern vlib_node_registration_t hicn_data_input_ip6_node;
extern vlib_node_registration_t hicn_data_input_ip4_node;

void
hicn_handoff_init()
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  uword *p;

  vlib_thread_registration_t *tr;
  /* Only the standard vnet worker threads are supported */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (p)
    {
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
	{
	  hicn_handoff_main.num_workers = tr->count;
	  hicn_handoff_main.first_worker_index = tr->first_index;
	}
    }

  hicn_handoff_main.frame_queue_index_interest_4 =  vlib_frame_queue_main_init (hicn4_iface_input_node.index, 0);
  hicn_handoff_main.frame_queue_index_interest_6 =  vlib_frame_queue_main_init (hicn6_iface_input_node.index, 0);
  hicn_handoff_main.frame_queue_index_data_6 =  vlib_frame_queue_main_init (hicn_data_input_ip6_node.index, 0);
  hicn_handoff_main.frame_queue_index_data_4 =  vlib_frame_queue_main_init (hicn_data_input_ip4_node.index, 0);
}

static_always_inline u64
get_hash_key(const ip6_header_t * header, u8 is_interest)
{
  const u64 *address = header->src_address.as_u64 + is_interest * 2;
  return address[0] + address[1];
}

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

static_always_inline uword
hicn_handoff_fn_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * frame, u32 frame_queue_index,
			u8 is_interest)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 n_enq, n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  hicn_main_t *sm = get_hicn_main();

  u32 n_workers = vec_len(sm->workers);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  /* TODO Quad Loop */
  while (n_left_from > 0)
    {
      
      u32 hash;
      u64 hash_key;
      u32 index0;

      hash_key = get_hash_key ((ip6_header_t *) vlib_buffer_get_current (b[0]), is_interest);
      hash = (u32) clib_xxhash (hash_key);

      if (PREDICT_TRUE (is_pow2 (n_workers)))
	index0 = hash & (n_workers - 1);
      else
	index0 = hash % n_workers;

      /* TODO This will handoff packets also to thread 0. */
      ti[0] = index0;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  hicn_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  u32 sw_if_index0;
	  sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  t->sw_if_index = sw_if_index0;
	  t->next_worker_index = ti[0];
	  t->buffer_index = vlib_get_buffer_index (vm, b[0]);
	}

      /* next */
      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, frame_queue_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 HICNFWD_ERROR_WORKER_HANDOFF_CONGESTION,
				 frame->n_vectors - n_enq);
  
  return frame->n_vectors;
}

VLIB_NODE_FN (hicn_data_handoff_4_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			    	  	 vlib_frame_t * frame)
{
  return hicn_handoff_fn_inline(vm, node, frame, hicn_handoff_main.frame_queue_index_data_6, /* is_interest */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_data_handoff_4_node) = {
  .name = "hicn-data-handoff-4",
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
/* *INDENT-ON* */

VLIB_NODE_FN (hicn_interest_handoff_4_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			    	  vlib_frame_t * frame)
{
  return hicn_handoff_fn_inline(vm, node, frame, hicn_handoff_main.frame_queue_index_interest_4, /* is_interest */ 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_interest_handoff_4_node) = {
  .name = "hicn-interest-handoff-4",
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
/* *INDENT-ON* */

VLIB_NODE_FN (hicn_data_handoff_6_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			    	  	 vlib_frame_t * frame)
{
  return hicn_handoff_fn_inline(vm, node, frame, hicn_handoff_main.frame_queue_index_data_6, /* is_interest */ 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_data_handoff_6_node) = {
  .name = "hicn-data-handoff-6",
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
/* *INDENT-ON* */

VLIB_NODE_FN (hicn_interest_handoff_6_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			    	  vlib_frame_t * frame)
{
  return hicn_handoff_fn_inline(vm, node, frame, hicn_handoff_main.frame_queue_index_interest_6, /* is_interest */ 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_interest_handoff_6_node) = {
  .name = "hicn-interest-handoff-6",
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
/* *INDENT-ON* */


/* *INDENT-OFF* */
VNET_FEATURE_INIT(hicn_data_input_ip6_arc, static)=
    {
     .arc_name = "ip6-local",
     .node_name = "hicn-data-handoff-6",
     .runs_before = VNET_FEATURES("ip6-local-end-of-arc"),
    };
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT(hicn_data_input_ip4_arc, static)=
    {
     .arc_name = "ip4-local",
     .node_name = "hicn-data-handoff-4",
     .runs_before = VNET_FEATURES("ip4-local-end-of-arc"),
    };
/* *INDENT-ON* */