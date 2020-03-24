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

typedef enum _hicn_hs_input_next
{
  HICN_HS_INPUT_NEXT_DATA,
  HICN_HS_INPUT_NEXT_INTEREST,
  HICN_HS_INPUT_NEXT_DROP,
  HICN_HS_INPUT_N_NEXT
} hicn_hs_input_next_t;

#define foreach_hicn_hs_input_next4                 \
  _ (DATA, HICN_HS_INPUT_DATA_NODE_NAME)	    \
  _ (INTEREST, HICN_HS_INPUT_INTEREST_NODE_NAME)    \
  _ (DROP, "ip4-drop")

#define foreach_hicn_hs_input_next6                 \
  _ (DATA, HICN_HS_INPUT_DATA_NODE_NAME)	    \
  _ (INTEREST, HICN_HS_INPUT_INTEREST_NODE_NAME)    \
  _ (DROP, "ip6-drop")

/* packet trace format function */
static u8 *
format_hicn_hs_input4_trace (u8 * s, va_list * args)
{
  return NULL;
}

static u8 *
format_hicn_hs_input6_trace (u8 * s, va_list * args)
{
  return NULL;
}

static u8 *
format_hicn_hs_input_interest_trace (u8 * s, va_list * args)
{
  return NULL;
}

static u8 *
format_hicn_hs_input_data_trace (u8 * s, va_list * args)
{
  return NULL;
}

static void
hicn_hs_input_trace_frame (vlib_main_t * vm, vlib_node_runtime_t * node,
		       vlib_buffer_t ** bs, u32 n_bufs, u8 is_ip4)
{
}

always_inline hicn_hs_ctx_t *
hicn_hs_input_lookup_buffer (vlib_buffer_t * b, u8 thread_index, u32 * error,
			     u8 is_ip4)
{
  hicn_hs_ctx_t *ctx = 0;
  hicn_header_t *hicn;
  hicn_hs_buffer_t *buffer;
  u32 ctx_index;
  int ret;

  hicn = hicn_buffer_hdr (b);
  buffer = hicn_hs_buffer (b);
  ret = hicn_packet_test_ece(hicn, (bool *)(&buffer->is_interest));

  if (PREDICT_FALSE(ret < 0))
    {
      *error = HICN_HS_ERROR_NO_HICN;
      return ctx;
    }
  
  if (buffer->is_interest)
    ctx_index = vnet_buffer (b)->ip.adj_index[VLIB_TX];
  else
    ctx_index = vnet_buffer (b)->ip.adj_index[VLIB_TX];

  ctx = hicn_hs_get_ctx_by_index(ctx_index, thread_index);

  if (PREDICT_FALSE(!ctx))
    *error = HICN_HS_ERROR_WRONG_THREAD;

  return ctx;
}

static inline void
hicn_hs_input_dispatch_buffer (hicn_hs_main_t * hm, hicn_hs_ctx_t * ctx,
			       vlib_buffer_t * b, u16 * next,
			       vlib_node_runtime_t * error_node)
{
  u32 error;
  hicn_hs_buffer_t *buffer = hicn_hs_buffer (b);
  *next = hm->dispatch_table[buffer->is_interest].next;
  error = hm->dispatch_table[buffer->is_interest].error;
  b->error = error_node->errors[error];
}

always_inline void
hicn_hs_input_set_error_next (hicn_hs_main_t * tm, u16 * next, u32 * error, u8 is_ip4)
{
  *next = HICN_HS_INPUT_NEXT_DROP;
}

always_inline uword
hicn_hs_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame, u8 is_ip4)
{
  u32 n_left_from, *from, thread_index = vm->thread_index;
  hicn_hs_main_t *hm = hicn_hs_get_main ();
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_node_runtime_t *error_node;

//   tcp_set_time_now (tcp_get_worker (thread_index));

  error_node = vlib_node_get_runtime (vm, is_ip4 ? hicn_hs_input4_node.index : hicn_hs_input6_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  next = nexts;

  while (n_left_from >= 4)
    {
      u32 error0 = HICN_HS_ERROR_NO_CONTEXT, error1 = HICN_HS_ERROR_NO_CONTEXT;
      hicn_hs_ctx_t *ctx0, *ctx1;

      {
	vlib_prefetch_buffer_header (b[2], STORE);
	CLIB_PREFETCH (b[2]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);

	vlib_prefetch_buffer_header (b[3], STORE);
	CLIB_PREFETCH (b[3]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
      }

      next[0] = next[1] = HICN_HS_INPUT_NEXT_DROP;

      ctx0 = hicn_hs_input_lookup_buffer (b[0], thread_index, &error0, is_ip4);
      ctx1 = hicn_hs_input_lookup_buffer (b[1], thread_index, &error1, is_ip4);

      if (PREDICT_TRUE (!ctx0 + !ctx1 == 0))
	{
	  hicn_hs_input_dispatch_buffer (hm, ctx0, b[0], &next[0], error_node);
	  hicn_hs_input_dispatch_buffer (hm, ctx1, b[1], &next[1], error_node);
	}
      else
	{
	  if (PREDICT_TRUE (ctx0 != 0))
	    {
	      hicn_hs_input_dispatch_buffer (hm, ctx0, b[0], &next[0], error_node);
	    }
	  else
	    {
	      hicn_hs_input_set_error_next (hm, &next[0], &error0, is_ip4);
	      b[0]->error = error_node->errors[error0];
	    }

	  if (PREDICT_TRUE (ctx1 != 0))
	    {
	      hicn_hs_input_dispatch_buffer (hm, ctx1, b[1], &next[1], error_node);
	    }
	  else
	    {
	      hicn_hs_input_set_error_next (hm, &next[1], &error1, is_ip4);
	      b[1]->error = error_node->errors[error1];
	    }
	}

      b += 2;
      next += 2;
      n_left_from -= 2;
    }
  while (n_left_from > 0)
    {
      hicn_hs_ctx_t *ctx0;
      u32 error0 = HICN_HS_ERROR_NO_CONTEXT;

      if (n_left_from > 1)
	{
	  vlib_prefetch_buffer_header (b[1], STORE);
	  CLIB_PREFETCH (b[1]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	}

      next[0] = HICN_HS_INPUT_NEXT_DROP;
      ctx0 = hicn_hs_input_lookup_buffer (b[0], thread_index, &error0, is_ip4);
      if (PREDICT_TRUE (ctx0 != 0))
	{
	  hicn_hs_input_dispatch_buffer (hm, ctx0, b[0], &next[0], error_node);
	}
      else
	{
	  hicn_hs_input_set_error_next (hm, &next[0], &error0, is_ip4);
	  b[0]->error = error_node->errors[error0];
	}

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    hicn_hs_input_trace_frame (vm, node, bufs, frame->n_vectors, is_ip4);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

static uword
hicn_hs_input_data (vlib_main_t * vm, vlib_node_runtime_t * node,
	    	    vlib_frame_t * frame)
{
  return frame->n_vectors;
}

static uword
hicn_hs_input_interest (vlib_main_t * vm, vlib_node_runtime_t * node,
	    	        vlib_frame_t * frame)
{
  return frame->n_vectors;
}

static uword
hicn_hs_input4 (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return hicn_hs_input_inline (vm, node, frame, 1);
}

static uword
hicn_hs_input6 (vlib_main_t * vm, vlib_node_runtime_t * node,
	    vlib_frame_t * frame)
{
  return hicn_hs_input_inline (vm, node, frame, 0);
}

/* *INDENT-OFF* */

VLIB_REGISTER_NODE (hicn_hs_input_interest_node) =
{
  .function = hicn_hs_input_data,
  .name = HICN_HS_INPUT_INTEREST_NODE_NAME,
  .vector_size = sizeof (u32),
  .format_trace = format_hicn_hs_input_interest_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HICN_HS_N_ERROR,
  .error_strings = hicn_hs_error_strings,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (hicn_hs_input_data_node) =
{
  .function = hicn_hs_input_interest,
  .name = HICN_HS_INPUT_DATA_NODE_NAME,
  .vector_size = sizeof (u32),
  .format_trace = format_hicn_hs_input_data_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HICN_HS_N_ERROR,
  .error_strings = hicn_hs_error_strings,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (hicn_hs_input4_node) =
{
  .function = hicn_hs_input4,
  .name = HICN_HS_INPUT4_NODE_NAME,
  .vector_size = sizeof (u32),
  .format_trace = format_hicn_hs_input4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HICN_HS_N_ERROR,
  .error_strings = hicn_hs_error_strings,
  .n_next_nodes = HICN_HS_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [HICN_HS_INPUT_NEXT_##s] = n,
    foreach_hicn_hs_input_next4
#undef _
  },
};

VLIB_REGISTER_NODE (hicn_hs_input6_node) =
{
  .function = hicn_hs_input6,
  .name = HICN_HS_INPUT6_NODE_NAME,
  .vector_size = sizeof (u32),
  .format_trace = format_hicn_hs_input6_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = HICN_HS_N_ERROR,
  .error_strings = hicn_hs_error_strings,
  .n_next_nodes = HICN_HS_INPUT_N_NEXT,
  .next_nodes =
  {
#define _(s,n) [HICN_HS_INPUT_NEXT_##s] = n,
    foreach_hicn_hs_input_next6
#undef _
  },
};

/* *INDENT-ON* */

static void
hicn_hs_dispatch_table_init (hicn_hs_main_t * tm)
{
  int i;
  for (i = 0; i < ARRAY_LEN (tm->dispatch_table); i++)
    {
      tm->dispatch_table[i].next = HICN_HS_INPUT_NEXT_DROP;
      tm->dispatch_table[i].error = HICN_HS_ERROR_DISPATCH;
    }

#define _(t,n,e)                                           	\
do {                                                       	\
    tm->dispatch_table[HICN_HS_##t].next = (n);         	\
    tm->dispatch_table[HICN_HS_##t].error = (e);        	\
} while (0)

  _ (INTEREST, HICN_HS_INPUT_NEXT_INTEREST, HICN_HS_ERROR_NONE);
  _ (DATA, HICN_HS_INPUT_NEXT_DATA, HICN_HS_ERROR_NONE);

#undef _
}

static clib_error_t *
hicn_hs_input_init (vlib_main_t * vm)
{
  hicn_hs_main_t *hm = hicn_hs_get_main ();

  /* Initialize dispatch table. */
  hicn_hs_dispatch_table_init (hm);

  return 0;
}

VLIB_INIT_FUNCTION (hicn_hs_input_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
