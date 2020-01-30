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

/**
 * @file
 *
 * @brief Application interface node
 *
 * This node runs after the device-input node and perfoms some safety checks in
 * order to avoid unespected interest and data (i.e., hICN packets whose name do
 * not contain the prefix associated to the application face)
 */

#include "face_prod.h"
#include "../../hicn_api.h"
#include "../../mgmt.h"

static __clib_unused char *face_prod_input_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

/* Node context data */
typedef struct hicn_face_prod_runtime_s
{
  int id;
} hicn_face_prod_runtime_t;

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} hicn_face_prod_input_trace_t;

typedef enum
{
  HICN_FACE_PROD_NEXT_DATA_IP4,
  HICN_FACE_PROD_NEXT_DATA_IP6,
  HICN_FACE_PROD_NEXT_ERROR_DROP,
  HICN_FACE_PROD_N_NEXT,
} hicn_face_prod_next_t;

vlib_node_registration_t hicn_face_prod_input_node;

static __clib_unused u8 *
format_face_prod_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_face_prod_input_trace_t *t =
    va_arg (*args, hicn_face_prod_input_trace_t *);
  CLIB_UNUSED (u32 indent) = format_get_indent (s);

  s = format (s, "prod-face: sw_if_index %d next-index %d",
	      t->sw_if_index, t->next_index);
  return s;
}

static_always_inline int
match_ip4_name (u32 * name, fib_prefix_t * prefix)
{
  u32 xor = 0;

  xor = *name & prefix->fp_addr.ip4.data_u32;

  return xor == prefix->fp_addr.ip4.data_u32;
}

static_always_inline int
match_ip6_name (u8 * name, fib_prefix_t * prefix)
{
  union
  {
    u32x4 as_u32x4;
    u64 as_u64[2];
    u32 as_u32[4];
  } xor_sum __attribute__ ((aligned (sizeof (u32x4))));

  xor_sum.as_u64[0] = ((u64 *) name)[0] & prefix->fp_addr.ip6.as_u64[0];
  xor_sum.as_u64[1] = ((u64 *) name)[1] & prefix->fp_addr.ip6.as_u64[1];

  return (xor_sum.as_u64[0] == prefix->fp_addr.ip6.as_u64[0]) &&
    (xor_sum.as_u64[1] == prefix->fp_addr.ip6.as_u64[1]);
}

static_always_inline u32
hicn_face_prod_next_from_data_hdr (vlib_node_runtime_t * node,
				   vlib_buffer_t * b, fib_prefix_t * prefix)
{
  u8 *ptr = vlib_buffer_get_current (b);
  u8 v = *ptr & 0xf0;
  int match_res = 1;

  if (PREDICT_TRUE (v == 0x40 && ip46_address_is_ip4 (&prefix->fp_addr)))
    {
      match_res = match_ip4_name ((u32 *) & (ptr[12]), prefix);
    }
  else if (PREDICT_TRUE (v == 0x60 && !ip46_address_is_ip4 (&prefix->fp_addr)))
    {
      match_res = match_ip6_name (& (ptr[8]), prefix);
    }

  return match_res ? HICN_FACE_PROD_NEXT_DATA_IP4 + (v ==
						     0x60) :
    HICN_FACE_PROD_NEXT_ERROR_DROP;
}

static_always_inline void
hicn_face_prod_trace_buffer (vlib_main_t * vm, vlib_node_runtime_t * node,
			     u32 swif, vlib_buffer_t * b, u32 next)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
		     (b->flags & VLIB_BUFFER_IS_TRACED)))
    {
      hicn_face_prod_input_trace_t *t =
	vlib_add_trace (vm, node, b, sizeof (*t));
      t->next_index = next;
      t->sw_if_index = swif;
    }
}

static uword
hicn_face_prod_input_node_fn (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  hicn_face_prod_next_t next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 bi0, bi1, bi2, bi3;
	  hicn_face_prod_state_t *prod_face0 = NULL;
	  hicn_face_prod_state_t *prod_face1 = NULL;
	  hicn_face_prod_state_t *prod_face2 = NULL;
	  hicn_face_prod_state_t *prod_face3 = NULL;
	  u32 next0, next1, next2, next3;

	  {
	    vlib_buffer_t *b4, *b5, *b6, *b7;
	    b4 = vlib_get_buffer (vm, from[4]);
	    b5 = vlib_get_buffer (vm, from[5]);
	    b6 = vlib_get_buffer (vm, from[6]);
	    b7 = vlib_get_buffer (vm, from[7]);
	    CLIB_PREFETCH (b4, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (b5, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (b6, CLIB_CACHE_LINE_BYTES, STORE);
	    CLIB_PREFETCH (b7, CLIB_CACHE_LINE_BYTES, STORE);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  bi2 = from[2];
	  bi3 = from[3];

	  from += 4;
	  n_left_from -= 4;
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  to_next[2] = bi2;
	  to_next[3] = bi3;

	  to_next += 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  prod_face0 =
	    &face_state_vec[vnet_buffer (b0)->sw_if_index[VLIB_RX]];
	  prod_face1 =
	    &face_state_vec[vnet_buffer (b1)->sw_if_index[VLIB_RX]];
	  prod_face2 =
	    &face_state_vec[vnet_buffer (b2)->sw_if_index[VLIB_RX]];
	  prod_face3 =
	    &face_state_vec[vnet_buffer (b3)->sw_if_index[VLIB_RX]];

	  next0 =
	    hicn_face_prod_next_from_data_hdr (node, b0, &prod_face0->prefix);
	  next1 =
	    hicn_face_prod_next_from_data_hdr (node, b1, &prod_face1->prefix);
	  next2 =
	    hicn_face_prod_next_from_data_hdr (node, b2, &prod_face2->prefix);
	  next3 =
	    hicn_face_prod_next_from_data_hdr (node, b3, &prod_face3->prefix);
	  stats.pkts_data_count += 4;

	  /* trace */
	  hicn_face_prod_trace_buffer (vm, node,
				       vnet_buffer (b0)->sw_if_index[VLIB_RX],
				       b0, next0);
	  hicn_face_prod_trace_buffer (vm, node,
				       vnet_buffer (b1)->sw_if_index[VLIB_RX],
				       b1, next1);
	  hicn_face_prod_trace_buffer (vm, node,
				       vnet_buffer (b2)->sw_if_index[VLIB_RX],
				       b2, next2);
	  hicn_face_prod_trace_buffer (vm, node,
				       vnet_buffer (b3)->sw_if_index[VLIB_RX],
				       b3, next3);

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);

	  stats.pkts_processed += 4;

	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0, swif;
	  hicn_face_prod_state_t *prod_face = NULL;
	  u32 next0;

	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *b1;
	      b1 = vlib_get_buffer (vm, from[1]);
	      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, STORE);
	    }

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  swif = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  prod_face = &face_state_vec[swif];

	  next0 =
	    hicn_face_prod_next_from_data_hdr (node, b0, &prod_face->prefix);
	  stats.pkts_data_count++;

	  /* trace */
	  hicn_face_prod_trace_buffer (vm, node,
				       vnet_buffer (b0)->sw_if_index[VLIB_RX],
				       b0, next0);

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  stats.pkts_processed += 1;

	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       HICNFWD_ERROR_PROCESSED, stats.pkts_processed);
  vlib_node_increment_counter (vm, node->node_index, HICNFWD_ERROR_DATAS,
			       stats.pkts_data_count);

  return (frame->n_vectors);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn_face_prod_input_node) =
{
  .function = hicn_face_prod_input_node_fn,
  .name = "hicn-face-prod-input",
  .vector_size = sizeof(u32),
  .format_trace = format_face_prod_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(face_prod_input_error_strings),
  .error_strings = face_prod_input_error_strings,
  .n_next_nodes = HICN_FACE_PROD_N_NEXT,
  .next_nodes =
  {
    [HICN_FACE_PROD_NEXT_DATA_IP4] = "hicn-face-ip4-input",
    [HICN_FACE_PROD_NEXT_DATA_IP6] = "hicn-face-ip6-input",
    [HICN_FACE_PROD_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
