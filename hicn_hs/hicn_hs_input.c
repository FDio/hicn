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

static char *hicn_hs_input_error_strings[] = {
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
