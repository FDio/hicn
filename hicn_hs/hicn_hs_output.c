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

/*
 * Error def for output node.
 */
static char *hicn_hs_output_error_strings[] = {
#define hicn_hs_error(n,s) s,
#include "errors/hicn_hs_output_node.def"
#undef hicn_hs_error
};

/**
 * Next nodes.
 */
#define foreach_hicn_hs_output_next				\
  _ (INTEREST_PCS_LOOKUP, "hicn-interest-pcslookup")		\
  _ (DATA_PCS_LOOKUP, "hicn-data-pcslookup")			\
  _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) HICN_HS_OUTPUT_NEXT_##s,
  foreach_hicn_hs_output_next
#undef _
    HICN_HS_OUTPUT_N_NEXT,
} hicn_hs_input_next_t;

static u8 *
format_hicn_hs_encap_trace (u8 * s, va_list * args)
{
  return NULL;
}

always_inline uword
hicn_hs_encap_inline (vlib_main_t * vm,
		      vlib_node_runtime_t * node,
		      vlib_frame_t * frame, int is_encap_v6)
{
  /* XXX Should the ipv6 header pushed in front of the packet here or in the push_header function directly? */
  return frame->n_vectors;
}

static uword
hicn_hs_encap_node_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  return hicn_hs_encap_inline (vm, node, frame, 1);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_hs_encap_node) = {
  .function = hicn_hs_encap_node_fn,
  .name = HICN_HS_INPUT_NODE_NAME,
  .vector_size = sizeof (u32),
  .format_trace = format_hicn_hs_encap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_hs_output_error_strings),
  .error_strings = hicn_hs_output_error_strings,
  .n_next_nodes = HICN_HS_OUTPUT_N_NEXT,
  .next_nodes = {
#define _(s, n) [HICN_HS_OUTPUT_NEXT_##s] = n,
      foreach_hicn_hs_output_next
#undef _
  },
};
