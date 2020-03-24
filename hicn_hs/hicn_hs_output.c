/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <vlibmemory/api.h>
#include <vlib/vlib.h>

#include <hicn_hs/hicn_hs.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>
#include <vnet/udp/udp.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/session/session.h>

typedef enum _hicn_hs_output_error
{
#define hicn_hs_error(n,s) HICN_HS_OUTPUT_ERROR_##n,
#include "errors/hicn_hs_output_node.def"
#undef hicn_hs_error
  HICN_HS_OUTPUT_N_ERROR,
} hicn_hs_output_error_t;

/*
 * Error def for output node.
 */
char *hicn_hs_output_error_strings[] = {
#define hicn_hs_error(n,s) s,
#include "errors/hicn_hs_output_node.def"
#undef hicn_hs_error
};

typedef enum _hicn_hs_output_next
{
  HICN_HS_OUTPUT_NEXT_IP_LOOKUP,
  HICN_HS_OUTPUT_NEXT_DROP,
  HICN_HS_OUTPUT_N_NEXT
} hicn_hs_output_next_t;

/**
 * Next nodes.
 */
#define foreach_hicn_hs_output4_next		\
  _ (IP_LOOKUP, "ip4-lookup")			\
  _ (DROP, "error-drop")


#define foreach_hicn_hs_output6_next		\
  _ (IP_LOOKUP, "ip6-lookup")			\
  _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) HICN_HS_OUTPUT4_NEXT_##s,
  foreach_hicn_hs_output4_next
#undef _
    HICN_HS_OUTPUT4_N_NEXT,
} hicn_hs_output4_next_t;

typedef enum
{
#define _(s, n) HICN_HS_OUTPUT6_NEXT_##s,
  foreach_hicn_hs_output6_next
#undef _
    HICN_HS_OUTPUT6_N_NEXT,
} hicn_hs_output6_next_t;

typedef struct
{
  u32 next_index;
  hicn_name_t name;
} hicn_hs_output_trace_t;

always_inline u8 *
format_hicn_hs_output_trace_i (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_hs_output_trace_t *t = va_arg (*args, hicn_hs_output_trace_t *);
  char name[64];
  u32 indent = format_get_indent (s);

  hicn_name_ntop(&t->name, name, 64);
  s = format (s, "hicn_hs_output: next-index %d",  t->next_index);
  s = format (s, "\n%Upacket: name %s", format_white_space, indent + 2,
	      name);
  return s;
}

static u8 *
format_hicn_hs_output4_trace (u8 * s, va_list * args)
{
  return format_hicn_hs_output_trace_i(s, args);
}

static u8 *
format_hicn_hs_output6_trace (u8 * s, va_list * args)
{
  return format_hicn_hs_output_trace_i(s, args);
}

static_always_inline void
hicn_hs_trace_buffer (vlib_main_t * vm, vlib_node_runtime_t * node,
                      vlib_buffer_t * b, u32 next, uword * n_tracep)
{
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  if (PREDICT_TRUE (b != 0))
    {
      hicn_hs_output_trace_t *tr;
      vlib_trace_buffer (vm, node, next, b, /* follow_chain */ 0);
      vlib_set_trace_count (vm, node, --(*n_tracep));
      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
      tr->next_index = next;
      hicn_interest_get_name(HF_INET6_TCP,
      			    (const hicn_header_t *)vlib_buffer_get_current(b),
			    &tr->name);
    }
}

always_inline uword
hicn_hs_output_inline (vlib_main_t * vm,
		      vlib_node_runtime_t * node,
		      vlib_frame_t * frame, int is_ip4)
{
  u32 n_left_from, *from, thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_node_runtime_t *error_node;

  uword n_trace = vlib_get_trace_count (vm, node);

  u32 node_index = is_ip4 ? hicn_hs_output4_node.index : hicn_hs_output6_node.index;
  error_node = vlib_node_get_runtime (vm, node_index);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from >= 4)
    {
      hicn_hs_ctx_t *hc0, *hc1;

      {
	vlib_prefetch_buffer_header (b[2], STORE);
	CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);

	vlib_prefetch_buffer_header (b[3], STORE);
	CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
      }

      hc0 = hicn_hs_get_ctx_by_index (hicn_hs_buffer (b[0])->ctx_index, thread_index);
      hc1 = hicn_hs_get_ctx_by_index (hicn_hs_buffer (b[1])->ctx_index, thread_index);

      if (PREDICT_TRUE (!hc0 + !hc1 == 0))
	{
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = hc0->c_fib_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_RX] = 0;
	  next[0] = HICN_HS_OUTPUT_NEXT_IP_LOOKUP;
	  vnet_buffer (b[1])->sw_if_index[VLIB_TX] = hc1->c_fib_index;
	  vnet_buffer (b[1])->sw_if_index[VLIB_RX] = 0;
	  next[1] = HICN_HS_OUTPUT_NEXT_IP_LOOKUP;

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      hicn_hs_trace_buffer (vm, node, b[0], next[0], &n_trace);
	      if (PREDICT_FALSE (n_trace > 0))
		hicn_hs_trace_buffer (vm, node, b[1], next[1], &n_trace);
	    }
	}
      else
	{
	  if (hc0 != 0)
	    {
	      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = hc0->c_fib_index;
	      vnet_buffer (b[0])->sw_if_index[VLIB_RX] = 0;
	      next[0] = HICN_HS_OUTPUT_NEXT_IP_LOOKUP;
	    }
	  else
	    {
	      b[0]->error = error_node->errors[HICN_HS_OUTPUT_ERROR_INVALID_CONNECTION];
	      next[0] = HICN_HS_OUTPUT_NEXT_DROP;
	    }
		
	  if (PREDICT_FALSE (n_trace > 0))
	    hicn_hs_trace_buffer (vm, node, b[0], next[0], &n_trace);

	  if (hc1 != 0)
	    {
	      vnet_buffer (b[1])->sw_if_index[VLIB_TX] = hc1->c_fib_index;
	      vnet_buffer (b[1])->sw_if_index[VLIB_RX] = 0;
	      next[1] = HICN_HS_OUTPUT_NEXT_IP_LOOKUP;
	    }
	  else
	    {
	      b[1]->error = error_node->errors[HICN_HS_OUTPUT_ERROR_INVALID_CONNECTION];
	      next[1] = HICN_HS_OUTPUT_NEXT_DROP;
	    }

	  if (PREDICT_FALSE (n_trace > 0))
	    hicn_hs_trace_buffer (vm, node, b[1], next[1], &n_trace);
	}

      b += 2;
      next += 2;
      n_left_from -= 2;
    }
  while (n_left_from > 0)
    {
      hicn_hs_ctx_t *hc0;

      if (n_left_from > 1)
	{
	  vlib_prefetch_buffer_header (b[1], STORE);
	  CLIB_PREFETCH (b[1]->data, 2 * CLIB_CACHE_LINE_BYTES, STORE);
	}

      hc0 = hicn_hs_get_ctx_by_index (hicn_hs_buffer (b[0])->ctx_index, thread_index);

      if (PREDICT_TRUE (hc0 != 0))
	{
	  vnet_buffer (b[0])->sw_if_index[VLIB_TX] = hc0->c_fib_index;
	  vnet_buffer (b[0])->sw_if_index[VLIB_RX] = 0;
	  next[0] = HICN_HS_OUTPUT_NEXT_IP_LOOKUP;
	}
      else
	{
	  b[0]->error = error_node->errors[HICN_HS_OUTPUT_ERROR_INVALID_CONNECTION];
	  next[0] = HICN_HS_OUTPUT_NEXT_DROP;
	}

	if (PREDICT_FALSE (n_trace > 0))
	  hicn_hs_trace_buffer (vm, node, b[0], next[0], &n_trace);

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, node_index, HICN_HS_OUTPUT_ERROR_PACKETS_SENT, frame->n_vectors);
  return frame->n_vectors;
}

static uword
hicn_hs_output4_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  return hicn_hs_output_inline (vm, node, frame, 1);
}

static uword
hicn_hs_output6_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  return hicn_hs_output_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_hs_output4_node) = {
  .function = hicn_hs_output4_node_fn,
  .name = HICN_HS_OUTPUT4_NODE_NAME,
  .vector_size = sizeof (u32),
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_hicn_hs_output4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_hs_output_error_strings),
  .error_strings = hicn_hs_output_error_strings,
  .n_next_nodes = HICN_HS_OUTPUT4_N_NEXT,
  .next_nodes = {
#define _(s, n) [HICN_HS_OUTPUT4_NEXT_##s] = n,
      foreach_hicn_hs_output4_next
#undef _
  },
};

VLIB_REGISTER_NODE (hicn_hs_output6_node) = {
  .function = hicn_hs_output6_node_fn,
  .name = HICN_HS_OUTPUT6_NODE_NAME,
  .vector_size = sizeof (u32),
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_hicn_hs_output6_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_hs_output_error_strings),
  .error_strings = hicn_hs_output_error_strings,
  .n_next_nodes = HICN_HS_OUTPUT6_N_NEXT,
  .next_nodes = {
#define _(s, n) [HICN_HS_OUTPUT6_NEXT_##s] = n,
      foreach_hicn_hs_output6_next
#undef _
  },
};

/* *INDENT-ON* */