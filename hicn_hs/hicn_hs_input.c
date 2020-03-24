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

char *hicn_hs_input_error_strings[] = {
#define hicn_hs_error(n,s) s,
#include "errors/hicn_hs_input_node.def"
#undef hicn_hs_error
};

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

always_inline uword
hicn_hs_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame, u8 is_ip4)
{
  /* Process incoming Interest/Data here */
  u32 n_left_from, *from;
  u32  *first_buffer;
  // u32 my_thread_index = vm->thread_index;

  from = first_buffer = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 ctx_idx;
  CLIB_UNUSED(vnet_buffer_opaque_t *buffer);

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
//       u32 error0 = UDP_ERROR_ENQUEUED;
//       udp_header_t *udp0;
//       ip4_header_t *ip40;
//       ip6_header_t *ip60;
//       u8 *data0;
//       session_t *s0;
//      udp_connection_t *uc0, *child0, *new_uc0;
//       transport_connection_t *tc0;
//       int wrote0;
//       void *rmt_addr, *lcl_addr;
//       session_dgram_hdr_t hdr0;
//       u8 queue_event = 1;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      /* udp_local hands us a pointer to the udp data */
//       data0 = vlib_buffer_get_current (b0);

      ctx_idx = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
      buffer= vnet_buffer (b0);
    }

    return ctx_idx;
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
VLIB_REGISTER_NODE (hicn_hs_input4_node) =
{
  .function = hicn_hs_input4,
  .name = HICN_HS_INPUT4_NODE_NAME,
  .vector_size = sizeof (u32),
  .format_trace = format_hicn_hs_input4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_hs_input_error_strings),
  .error_strings = hicn_hs_input_error_strings,
  .n_next_nodes = 0,
};

VLIB_REGISTER_NODE (hicn_hs_input6_node) =
{
  .function = hicn_hs_input6,
  .name = HICN_HS_INPUT6_NODE_NAME,
  .vector_size = sizeof (u32),
  .format_trace = format_hicn_hs_input6_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_hs_input_error_strings),
  .error_strings = hicn_hs_input_error_strings,
  .n_next_nodes = 0,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
