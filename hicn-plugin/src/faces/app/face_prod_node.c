/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 * order to avoid unespected interest and data (i.e., hICN packets whose name
 * do not contain the prefix associated to the application face)
 */

#include "face_prod.h"
#include "../../mgmt.h"
#include "../../parser.h"

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
  hicn_error_t error;
} hicn_face_prod_input_trace_t;

typedef enum
{
  HICN_FACE_PROD_NEXT_PCS,
  HICN_FACE_PROD_NEXT_ERROR_DROP,
  HICN_FACE_PROD_N_NEXT,
} hicn_face_prod_next_t;

vlib_node_registration_t hicn_face_prod_input_node;

static __clib_unused u8 *
format_face_prod_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_face_prod_input_trace_t *t =
    va_arg (*args, hicn_face_prod_input_trace_t *);
  CLIB_UNUSED (u32 indent) = format_get_indent (s);

  s = format (s, "prod-face: sw_if_index %d next-index %d", t->sw_if_index,
	      t->next_index);

  if (t->error != HICN_ERROR_NONE)
    s = format (s, " error %s", get_error_string (t->error));
  return s;
}

static_always_inline int
match_ip4_name (u32 *name, const fib_prefix_t *prefix)
{
  u32 xor = 0;

  xor = *name & prefix->fp_addr.ip4.data_u32;

  return xor == prefix->fp_addr.ip4.data_u32;
}

static_always_inline int
match_ip6_name (u8 *name, const fib_prefix_t *prefix)
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
hicn_face_prod_next_from_data_hdr (vlib_buffer_t *b)
{
  u8 is_v6;
  int match_res = 1;
  int ret = 0;
  hicn_name_t *name;
  hicn_face_prod_state_t *prod_face = NULL;

  // 1 - ensure the packet is hicn and its format is correct
  ret = hicn_data_parse_pkt (b);
  if (PREDICT_FALSE (ret))
    {
      return HICN_FACE_PROD_NEXT_ERROR_DROP;
    }

  // 2 - make sure the packet refers to a valid producer app state and
  // retrieve app state information
  prod_face = &face_state_vec[vnet_buffer (b)->sw_if_index[VLIB_RX]];
  vnet_buffer (b)->ip.adj_index[VLIB_RX] = prod_face->adj_index;

  // 3 - make sure the address in the packet belongs to the producer prefix
  // of this face
  const fib_prefix_t *prefix = &prod_face->prefix;
  is_v6 = hicn_buffer_is_v6 (b);
  name = &hicn_get_buffer (b)->name;
  if (PREDICT_TRUE (!is_v6 && ip46_address_is_ip4 (&prefix->fp_addr)))
    {
      match_res = match_ip4_name (&name->prefix.ip4.as_u32, prefix);
    }
  else if (PREDICT_TRUE (is_v6 && !ip46_address_is_ip4 (&prefix->fp_addr)))
    {
      match_res = match_ip6_name (name->prefix.ip6.as_u8, prefix);
    }

  // 4 - if match found, forward data to next hicn node
  return match_res ? HICN_FACE_PROD_NEXT_PCS : HICN_FACE_PROD_NEXT_ERROR_DROP;
}

static_always_inline void
hicn_face_prod_trace_buffer (vlib_main_t *vm, vlib_node_runtime_t *node,
			     u32 swif, vlib_buffer_t *b, u32 next)
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
hicn_face_prod_input_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next;
  hicn_face_prod_next_t next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  u32 thread_index = vm->thread_index;

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
	  hicn_buffer_t *hicnb0, *hicnb1, *hicnb2, *hicnb3;
	  u32 bi0, bi1, bi2, bi3;
	  u32 next0, next1, next2, next3;

	  // Prefetch next iteration
	  {
	    vlib_buffer_t *b4, *b5, *b6, *b7;
	    b4 = vlib_get_buffer (vm, from[4]);
	    b5 = vlib_get_buffer (vm, from[5]);
	    b6 = vlib_get_buffer (vm, from[6]);
	    b7 = vlib_get_buffer (vm, from[7]);
	    CLIB_PREFETCH (b4, 2 * CLIB_CACHE_LINE_BYTES, WRITE);
	    CLIB_PREFETCH (b5, 2 * CLIB_CACHE_LINE_BYTES, WRITE);
	    CLIB_PREFETCH (b6, 2 * CLIB_CACHE_LINE_BYTES, WRITE);
	    CLIB_PREFETCH (b7, 2 * CLIB_CACHE_LINE_BYTES, WRITE);

	    CLIB_PREFETCH (vlib_buffer_get_current (b4),
			   2 * CLIB_CACHE_LINE_BYTES, WRITE);
	    CLIB_PREFETCH (vlib_buffer_get_current (b5),
			   2 * CLIB_CACHE_LINE_BYTES, WRITE);
	    CLIB_PREFETCH (vlib_buffer_get_current (b6),
			   2 * CLIB_CACHE_LINE_BYTES, WRITE);
	    CLIB_PREFETCH (vlib_buffer_get_current (b7),
			   2 * CLIB_CACHE_LINE_BYTES, WRITE);
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

	  hicnb0 = hicn_get_buffer (b0);
	  hicnb1 = hicn_get_buffer (b1);
	  hicnb2 = hicn_get_buffer (b2);
	  hicnb3 = hicn_get_buffer (b3);

	  hicnb0->flags = HICN_FACE_FLAGS_DEFAULT;
	  hicnb1->flags = HICN_FACE_FLAGS_DEFAULT;
	  hicnb2->flags = HICN_FACE_FLAGS_DEFAULT;
	  hicnb3->flags = HICN_FACE_FLAGS_DEFAULT;

	  // parse packets and get next node
	  next0 = hicn_face_prod_next_from_data_hdr (b0);
	  next1 = hicn_face_prod_next_from_data_hdr (b1);
	  next2 = hicn_face_prod_next_from_data_hdr (b2);
	  next3 = hicn_face_prod_next_from_data_hdr (b3);
	  stats.pkts_data_count += 4;

	  // counters
	  vlib_increment_combined_counter (
	    &counters[hicnb0->face_id * HICN_N_COUNTER], thread_index,
	    HICN_FACE_COUNTERS_DATA_RX, 1,
	    vlib_buffer_length_in_chain (vm, b0));
	  stats.pkts_data_count += 1;

	  vlib_increment_combined_counter (
	    &counters[hicnb1->face_id * HICN_N_COUNTER], thread_index,
	    HICN_FACE_COUNTERS_DATA_RX, 1,
	    vlib_buffer_length_in_chain (vm, b0));
	  stats.pkts_data_count += 1;

	  vlib_increment_combined_counter (
	    &counters[hicnb2->face_id * HICN_N_COUNTER], thread_index,
	    HICN_FACE_COUNTERS_DATA_RX, 1,
	    vlib_buffer_length_in_chain (vm, b0));
	  stats.pkts_data_count += 1;

	  vlib_increment_combined_counter (
	    &counters[hicnb3->face_id * HICN_N_COUNTER], thread_index,
	    HICN_FACE_COUNTERS_DATA_RX, 1,
	    vlib_buffer_length_in_chain (vm, b0));
	  stats.pkts_data_count += 1;

	  // trace
	  hicn_face_prod_trace_buffer (
	    vm, node, vnet_buffer (b0)->sw_if_index[VLIB_RX], b0, next0);
	  hicn_face_prod_trace_buffer (
	    vm, node, vnet_buffer (b1)->sw_if_index[VLIB_RX], b1, next1);
	  hicn_face_prod_trace_buffer (
	    vm, node, vnet_buffer (b2)->sw_if_index[VLIB_RX], b2, next2);
	  hicn_face_prod_trace_buffer (
	    vm, node, vnet_buffer (b3)->sw_if_index[VLIB_RX], b3, next3);

	  // enqueue
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);

	  stats.pkts_processed += 4;
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  hicn_buffer_t *hicnb0;
	  u32 bi0;
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
	  hicnb0 = hicn_get_buffer (b0);
	  hicnb0->flags = HICN_FACE_FLAGS_DEFAULT;

	  next0 = hicn_face_prod_next_from_data_hdr (b0);
	  stats.pkts_data_count++;

	  // counters
	  vlib_increment_combined_counter (
	    &counters[hicnb0->face_id * HICN_N_COUNTER], thread_index,
	    HICN_FACE_COUNTERS_DATA_RX, 1,
	    vlib_buffer_length_in_chain (vm, b0));
	  stats.pkts_data_count += 1;

	  /* trace */
	  hicn_face_prod_trace_buffer (
	    vm, node, vnet_buffer (b0)->sw_if_index[VLIB_RX], b0, next0);

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  stats.pkts_processed += 1;
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, HICNFWD_ERROR_PROCESSED,
			       stats.pkts_processed);
  vlib_node_increment_counter (vm, node->node_index, HICNFWD_ERROR_DATAS,
			       stats.pkts_data_count);

  return (frame->n_vectors);
}

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
    [HICN_FACE_PROD_NEXT_PCS] = "hicn-data-pcslookup",
    [HICN_FACE_PROD_NEXT_ERROR_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */