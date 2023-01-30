/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

#include <vnet/adj/adj.h>

#include "face.h"
#include "inlines.h"
#include "face_node.h"
#include "../strategy_dpo_manager.h"
#include "face.h"
#include "../cache_policies/cs_lru.h"
#include "../infra.h"
#include "../hicn.h"
#include "../parser.h"

#include <hicn/error.h>
#include <hicn/util/ip_address.h>

/**
 * @File
 *
 * Definition of the nodes for ip incomplete faces.
 */

vlib_node_registration_t hicn4_face_input_node;
vlib_node_registration_t hicn4_face_output_node;
vlib_node_registration_t hicn6_face_input_node;
vlib_node_registration_t hicn6_face_output_node;

#define ip_v4 4
#define ip_v6 6

static char *hicn4_face_input_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static char *hicn6_face_input_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  hicn_error_t error;
  u8 packet_data[60];
} hicn4_face_input_trace_t;

typedef enum
{
  HICN4_FACE_INPUT_NEXT_DATA,
  HICN4_FACE_INPUT_NEXT_MAPME,
  HICN4_FACE_INPUT_NEXT_ERROR_DROP,
  HICN4_FACE_INPUT_N_NEXT,
} hicn4_face_input_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  hicn_error_t error;
  u8 packet_data[60];
} hicn6_face_input_trace_t;

typedef enum
{
  HICN6_FACE_INPUT_NEXT_DATA,
  HICN6_FACE_INPUT_NEXT_MAPME,
  HICN6_FACE_INPUT_NEXT_ERROR_DROP,
  HICN6_FACE_INPUT_N_NEXT,
} hicn6_face_input_next_t;

#define NEXT_MAPME_IP4 HICN4_FACE_INPUT_NEXT_MAPME
#define NEXT_MAPME_IP6 HICN6_FACE_INPUT_NEXT_MAPME

#define NEXT_DATA_IP4 HICN4_FACE_INPUT_NEXT_DATA
#define NEXT_DATA_IP6 HICN6_FACE_INPUT_NEXT_DATA

#define NEXT_ERROR_DROP_IP4 HICN4_FACE_INPUT_NEXT_ERROR_DROP
#define NEXT_ERROR_DROP_IP6 HICN6_FACE_INPUT_NEXT_ERROR_DROP

#define IP_HEADER_4 ip4_header_t
#define IP_HEADER_6 ip6_header_t

#define TRACE_INPUT_PKT_IP4 hicn4_face_input_trace_t
#define TRACE_INPUT_PKT_IP6 hicn6_face_input_trace_t

/*
 * NOTE: Both hicn4_face_input_node_fn and hicn6_face_input_node_fn
 * present a similar codebase. Macro are hard to debug, although the
 * followind code is pretty straighforward and most of the complexity is in
 * functions that can be easily debug.
 */
#define face_input_x1(ipv)                                                    \
  do                                                                          \
    {                                                                         \
      vlib_buffer_t *b0;                                                      \
      u32 bi0, sw_if0;                                                        \
      u32 next0 = NEXT_ERROR_DROP_IP##ipv;                                    \
      u8 is_mapme0;                                                           \
      IP_HEADER_##ipv *ip_hdr = NULL;                                         \
      hicn_buffer_t *hicnb0;                                                  \
      int from_tunnel0;                                                       \
      int ret0 = HICN_ERROR_NONE;                                             \
      /* Prefetch for next iteration. */                                      \
      if (n_left_from > 1)                                                    \
	{                                                                     \
	  vlib_buffer_t *b1;                                                  \
	  b1 = vlib_get_buffer (vm, from[1]);                                 \
	  CLIB_PREFETCH (b1, 2 * CLIB_CACHE_LINE_BYTES, STORE);               \
	  CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, LOAD);              \
	}                                                                     \
      /* Dequeue a packet buffer */                                           \
      bi0 = from[0];                                                          \
      from += 1;                                                              \
      n_left_from -= 1;                                                       \
      to_next[0] = bi0;                                                       \
      to_next += 1;                                                           \
      n_left_to_next -= 1;                                                    \
                                                                              \
      b0 = vlib_get_buffer (vm, bi0);                                         \
      hicnb0 = hicn_get_buffer (b0);                                          \
      ip_hdr = (IP_HEADER_##ipv *) vlib_buffer_get_current (b0);              \
                                                                              \
      /* Parse packet and cache useful info in opaque2 */                     \
      ret0 = hicn_data_parse_pkt (b0, vlib_buffer_length_in_chain (vm, b0));  \
      is_mapme0 = hicn_packet_get_type (&hicn_get_buffer (b0)->pkbuf) ==      \
		  HICN_PACKET_TYPE_MAPME;                                     \
                                                                              \
      ret0 = (ret0 == HICN_ERROR_NONE) ||                                     \
	     (ret0 == HICN_ERROR_PARSER_MAPME_PACKET);                        \
                                                                              \
      /* If parsing is ok, send packet to next node */                        \
      if (PREDICT_FALSE (!ret0))                                              \
	{                                                                     \
	  next0 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                     \
	}                                                                     \
      else                                                                    \
	{                                                                     \
	  next0 = is_mapme0 * NEXT_MAPME_IP##ipv +                            \
		  (1 - is_mapme0) * NEXT_DATA_IP##ipv;                        \
	  from_tunnel0 =                                                      \
	    (hicnb0->flags & HICN_BUFFER_FLAGS_FROM_UDP4_TUNNEL ||            \
	     hicnb0->flags & HICN_BUFFER_FLAGS_FROM_UDP6_TUNNEL) > 0;         \
	  sw_if0 =                                                            \
	    (from_tunnel0) * ~0 +                                             \
	    (1 - from_tunnel0) * vnet_buffer (b0)->sw_if_index[VLIB_RX];      \
                                                                              \
	  ret0 = hicn_face_ip##ipv##_find (                                   \
	    &hicnb0->face_id, &hicnb0->flags, &ip_hdr->dst_address, sw_if0,   \
	    vnet_buffer (b0)->ip.adj_index[VLIB_RX],                          \
	    /* Should not be used */ ~0);                                     \
	  /* Make sure the face is not created here */                        \
	  if (PREDICT_FALSE (ret0 == HICN_ERROR_FACE_NOT_FOUND))              \
	    {                                                                 \
	      next0 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                 \
	    }                                                                 \
	}                                                                     \
                                                                              \
      vlib_increment_combined_counter (                                       \
	&counters[hicnb0->face_id * HICN_N_COUNTER], thread_index,            \
	HICN_FACE_COUNTERS_DATA_RX, 1, vlib_buffer_length_in_chain (vm, b0)); \
      stats.pkts_data_count += 1;                                             \
                                                                              \
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&              \
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))                \
	{                                                                     \
	  TRACE_INPUT_PKT_IP##ipv *t =                                        \
	    vlib_add_trace (vm, node, b0, sizeof (*t));                       \
	  t->pkt_type = HICN_PACKET_TYPE_INTEREST;                            \
	  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];            \
	  t->error = ret0;                                                    \
	  t->next_index = next0;                                              \
	  clib_memcpy_fast (t->packet_data, vlib_buffer_get_current (b0),     \
			    sizeof (t->packet_data));                         \
	}                                                                     \
                                                                              \
      /* Verify speculative enqueue, maybe switch current next frame */       \
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,         \
				       n_left_to_next, bi0, next0);           \
    }                                                                         \
  while (0)

#define face_input_x2(ipv)                                                    \
  do                                                                          \
    {                                                                         \
      vlib_buffer_t *b0, *b1;                                                 \
      u32 bi0, bi1, sw_if0, sw_if1;                                           \
      u32 next0 = NEXT_ERROR_DROP_IP##ipv;                                    \
      u32 next1 = NEXT_ERROR_DROP_IP##ipv;                                    \
      u8 is_mapme0, is_mapme1;                                                \
      IP_HEADER_##ipv *ip_hdr0 = NULL;                                        \
      IP_HEADER_##ipv *ip_hdr1 = NULL;                                        \
      hicn_buffer_t *hicnb0;                                                  \
      hicn_buffer_t *hicnb1;                                                  \
      int from_tunnel0, from_tunnel1;                                         \
      int ret0, ret1;                                                         \
      /* Prefetch for next iteration. */                                      \
      {                                                                       \
	vlib_buffer_t *b2, *b3;                                               \
	b2 = vlib_get_buffer (vm, from[2]);                                   \
	b3 = vlib_get_buffer (vm, from[3]);                                   \
	CLIB_PREFETCH (b2, 2 * CLIB_CACHE_LINE_BYTES, STORE);                 \
	CLIB_PREFETCH (b3, 2 * CLIB_CACHE_LINE_BYTES, STORE);                 \
	CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES, LOAD);                \
	CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES, LOAD);                \
      }                                                                       \
      /* Dequeue a packet buffer */                                           \
      bi0 = from[0];                                                          \
      bi1 = from[1];                                                          \
      from += 2;                                                              \
      n_left_from -= 2;                                                       \
      to_next[0] = bi0;                                                       \
      to_next[1] = bi1;                                                       \
      to_next += 2;                                                           \
      n_left_to_next -= 2;                                                    \
                                                                              \
      b0 = vlib_get_buffer (vm, bi0);                                         \
      b1 = vlib_get_buffer (vm, bi1);                                         \
      hicnb0 = hicn_get_buffer (b0);                                          \
      hicnb1 = hicn_get_buffer (b1);                                          \
      ip_hdr0 = (IP_HEADER_##ipv *) vlib_buffer_get_current (b0);             \
      ip_hdr1 = (IP_HEADER_##ipv *) vlib_buffer_get_current (b1);             \
                                                                              \
      /* Parse packet and cache useful info in opaque2 */                     \
      ret0 = hicn_data_parse_pkt (b0, vlib_buffer_length_in_chain (vm, b0));  \
      ret1 = hicn_data_parse_pkt (b1, vlib_buffer_length_in_chain (vm, b1));  \
      is_mapme0 = hicn_packet_get_type (&hicn_get_buffer (b0)->pkbuf) ==      \
		  HICN_PACKET_TYPE_MAPME;                                     \
      is_mapme1 = hicn_packet_get_type (&hicn_get_buffer (b1)->pkbuf) ==      \
		  HICN_PACKET_TYPE_MAPME;                                     \
      ret0 = (ret0 == HICN_ERROR_NONE) ||                                     \
	     (ret0 == HICN_ERROR_PARSER_MAPME_PACKET);                        \
      ret1 = (ret1 == HICN_ERROR_NONE) ||                                     \
	     (ret1 == HICN_ERROR_PARSER_MAPME_PACKET);                        \
      if (PREDICT_TRUE (ret0 && ret1))                                        \
	{                                                                     \
	  next0 = is_mapme0 * NEXT_MAPME_IP##ipv +                            \
		  (1 - is_mapme0) * NEXT_DATA_IP##ipv;                        \
                                                                              \
	  next1 = is_mapme1 * NEXT_MAPME_IP##ipv +                            \
		  (1 - is_mapme1) * NEXT_DATA_IP##ipv;                        \
                                                                              \
	  from_tunnel0 =                                                      \
	    (hicnb0->flags & HICN_BUFFER_FLAGS_FROM_UDP4_TUNNEL ||            \
	     hicnb0->flags & HICN_BUFFER_FLAGS_FROM_UDP6_TUNNEL) > 0;         \
	  sw_if0 =                                                            \
	    (from_tunnel0) * ~0 +                                             \
	    (1 - from_tunnel0) * vnet_buffer (b0)->sw_if_index[VLIB_RX];      \
                                                                              \
	  ret0 = hicn_face_ip##ipv##_find (                                   \
	    &hicnb0->face_id, &hicnb0->flags, &ip_hdr0->dst_address, sw_if0,  \
	    vnet_buffer (b0)->ip.adj_index[VLIB_RX],                          \
	    /* Should not be used */ ~0);                                     \
	  /* Make sure the face is not created here */                        \
	  if (PREDICT_FALSE (ret0 == HICN_ERROR_FACE_NOT_FOUND))              \
	    {                                                                 \
	      next0 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                 \
	    }                                                                 \
                                                                              \
	  from_tunnel1 =                                                      \
	    (hicnb1->flags & HICN_BUFFER_FLAGS_FROM_UDP4_TUNNEL ||            \
	     hicnb1->flags & HICN_BUFFER_FLAGS_FROM_UDP6_TUNNEL) > 0;         \
	  sw_if1 =                                                            \
	    (from_tunnel1) * ~0 +                                             \
	    (1 - from_tunnel1) * vnet_buffer (b1)->sw_if_index[VLIB_RX];      \
                                                                              \
	  ret1 = hicn_face_ip##ipv##_find (                                   \
	    &hicnb1->face_id, &hicnb1->flags, &ip_hdr1->dst_address, sw_if1,  \
	    vnet_buffer (b1)->ip.adj_index[VLIB_RX],                          \
	    /* Should not be used */ ~0);                                     \
	  /* Make sure the face is not created here */                        \
	  if (PREDICT_FALSE (ret1 == HICN_ERROR_FACE_NOT_FOUND))              \
	    {                                                                 \
	      next1 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                 \
	    }                                                                 \
	}                                                                     \
      else if (ret0 && !ret1)                                                 \
	{                                                                     \
	  next1 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                     \
	  from_tunnel0 =                                                      \
	    (hicnb0->flags & HICN_BUFFER_FLAGS_FROM_UDP4_TUNNEL ||            \
	     hicnb0->flags & HICN_BUFFER_FLAGS_FROM_UDP6_TUNNEL) > 0;         \
	  sw_if0 =                                                            \
	    (from_tunnel0) * ~0 +                                             \
	    (1 - from_tunnel0) * vnet_buffer (b0)->sw_if_index[VLIB_RX];      \
                                                                              \
	  ret0 = hicn_face_ip##ipv##_find (                                   \
	    &hicnb0->face_id, &hicnb0->flags, &ip_hdr0->dst_address, sw_if0,  \
	    vnet_buffer (b0)->ip.adj_index[VLIB_RX],                          \
	    /* Should not be used */ ~0);                                     \
	  /* Make sure the face is not created here */                        \
	  if (PREDICT_FALSE (ret0 == HICN_ERROR_FACE_NOT_FOUND))              \
	    {                                                                 \
	      next0 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                 \
	    }                                                                 \
	  else                                                                \
	    {                                                                 \
	      next0 = is_mapme0 * NEXT_MAPME_IP##ipv +                        \
		      (1 - is_mapme0) * NEXT_DATA_IP##ipv;                    \
	    }                                                                 \
	}                                                                     \
      else if (!ret0 && ret1)                                                 \
	{                                                                     \
	  next0 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                     \
	  from_tunnel1 =                                                      \
	    (hicnb1->flags & HICN_BUFFER_FLAGS_FROM_UDP4_TUNNEL ||            \
	     hicnb1->flags & HICN_BUFFER_FLAGS_FROM_UDP6_TUNNEL) > 0;         \
	  sw_if1 =                                                            \
	    (from_tunnel1) * ~0 +                                             \
	    (1 - from_tunnel1) * vnet_buffer (b1)->sw_if_index[VLIB_RX];      \
                                                                              \
	  ret1 = hicn_face_ip##ipv##_find (                                   \
	    &hicnb1->face_id, &hicnb1->flags, &ip_hdr1->dst_address, sw_if1,  \
	    vnet_buffer (b1)->ip.adj_index[VLIB_RX],                          \
	    /* Should not be used */ ~0);                                     \
	  /* Make sure the face is not created here */                        \
	  if (PREDICT_FALSE (ret1 == HICN_ERROR_FACE_NOT_FOUND))              \
	    {                                                                 \
	      next1 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                 \
	    }                                                                 \
	  else                                                                \
	    {                                                                 \
	      next1 = is_mapme1 * NEXT_MAPME_IP##ipv +                        \
		      (1 - is_mapme1) * NEXT_DATA_IP##ipv;                    \
	    }                                                                 \
	}                                                                     \
      else                                                                    \
	{                                                                     \
	  next0 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                     \
	  next1 = HICN##ipv##_FACE_INPUT_NEXT_ERROR_DROP;                     \
	}                                                                     \
                                                                              \
      vlib_increment_combined_counter (                                       \
	&counters[hicnb0->face_id * HICN_N_COUNTER], thread_index,            \
	HICN_FACE_COUNTERS_DATA_RX, 1, vlib_buffer_length_in_chain (vm, b0)); \
      stats.pkts_data_count += 1;                                             \
                                                                              \
      vlib_increment_combined_counter (                                       \
	&counters[hicnb1->face_id * HICN_N_COUNTER], thread_index,            \
	HICN_FACE_COUNTERS_DATA_RX, 1, vlib_buffer_length_in_chain (vm, b1)); \
      stats.pkts_data_count += 1;                                             \
                                                                              \
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&              \
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))                \
	{                                                                     \
	  TRACE_INPUT_PKT_IP##ipv *t =                                        \
	    vlib_add_trace (vm, node, b0, sizeof (*t));                       \
	  t->pkt_type = HICN_PACKET_TYPE_INTEREST;                            \
	  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];            \
	  t->error = ret0;                                                    \
	  t->next_index = next0;                                              \
	  clib_memcpy_fast (t->packet_data, vlib_buffer_get_current (b0),     \
			    sizeof (t->packet_data));                         \
	}                                                                     \
                                                                              \
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&              \
			 (b1->flags & VLIB_BUFFER_IS_TRACED)))                \
	{                                                                     \
	  TRACE_INPUT_PKT_IP##ipv *t =                                        \
	    vlib_add_trace (vm, node, b1, sizeof (*t));                       \
	  t->pkt_type = HICN_PACKET_TYPE_INTEREST;                            \
	  t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];            \
	  t->error = ret1;                                                    \
	  t->next_index = next1;                                              \
	  clib_memcpy_fast (t->packet_data, vlib_buffer_get_current (b1),     \
			    sizeof (t->packet_data));                         \
	}                                                                     \
                                                                              \
      /* Verify speculative enqueue, maybe switch current next frame */       \
      vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,         \
				       n_left_to_next, bi0, bi1, next0,       \
				       next1);                                \
    }                                                                         \
  while (0)

static uword
hicn4_face_input_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  u32 thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop, X2 */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  face_input_x2 (4);
	}

      /* Dual loop, X1 */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  face_input_x1 (4);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, HICNFWD_ERROR_DATAS,
			       stats.pkts_data_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn4_face_input_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn4_face_input_trace_t *t = va_arg (*args, hicn4_face_input_trace_t *);

  s = format (s, "FACE_IP4_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	      (int) t->pkt_type, t->sw_if_index, t->next_index,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
VLIB_REGISTER_NODE(hicn4_face_input_node) =
{
  .function = hicn4_face_input_node_fn,
  .name = "hicn4-face-input",
  .vector_size = sizeof(u32),
  .format_trace = hicn4_face_input_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn4_face_input_error_strings),
  .error_strings = hicn4_face_input_error_strings,
  .n_next_nodes = HICN4_FACE_INPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN4_FACE_INPUT_NEXT_DATA] = "hicn-data-pcslookup",
    [HICN4_FACE_INPUT_NEXT_MAPME] = "hicn-mapme-ack",
    [HICN4_FACE_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};

/**
 * @brief IPv6 face input node function
 * @see hicn6_face_input_node_fn
 */
static uword
hicn6_face_input_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  u32 thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop, X2 */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  face_input_x2 (6);
	}

      /* Dual loop, X1 */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  face_input_x1 (6);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, HICNFWD_ERROR_DATAS,
			       stats.pkts_data_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn6_face_input_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn6_face_input_trace_t *t = va_arg (*args, hicn6_face_input_trace_t *);

  s = format (s, "FACE_IP6_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	      (int) t->pkt_type, t->sw_if_index, t->next_index,
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
VLIB_REGISTER_NODE(hicn6_face_input_node) =
{
  .function = hicn6_face_input_node_fn,
  .name = "hicn6-face-input",
  .vector_size = sizeof(u32),
  .format_trace = hicn6_face_input_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn6_face_input_error_strings),
  .error_strings = hicn6_face_input_error_strings,
  .n_next_nodes = HICN6_FACE_INPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN6_FACE_INPUT_NEXT_DATA] = "hicn-data-pcslookup",
    [HICN6_FACE_INPUT_NEXT_MAPME] = "hicn-mapme-ack",
    [HICN6_FACE_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};

/**** FACE OUTPUT *****/

typedef enum
{
  HICN4_FACE_OUTPUT_NEXT_ERROR_DROP,
  HICN4_FACE_OUTPUT_NEXT_ECHO_REPLY,
  HICN4_FACE_OUTPUT_NEXT_UDP4_ENCAP,
  HICN4_FACE_OUTPUT_NEXT_UDP6_ENCAP,
  HICN4_FACE_OUTPUT_N_NEXT,
} hicn4_face_output_next_t;

typedef enum
{
  HICN6_FACE_OUTPUT_NEXT_ERROR_DROP,
  HICN6_FACE_OUTPUT_NEXT_ECHO_REPLY,
  HICN6_FACE_OUTPUT_NEXT_UDP4_ENCAP,
  HICN6_FACE_OUTPUT_NEXT_UDP6_ENCAP,
  HICN6_FACE_OUTPUT_N_NEXT,
} hicn6_face_output_next_t;

static inline void
hicn_face_rewrite_interest (vlib_main_t *vm, vlib_buffer_t *b0,
			    hicn_face_t *face, u32 *next)
{

  /* if ((face->flags & HICN_FACE_FLAGS_APPFACE_PROD) &&
   * hicn_face_match_probe(b0, face, next)) */
  /*   return; */

  hicn_packet_buffer_t *pkbuf = &hicn_get_buffer (b0)->pkbuf;

  u8 is_v4 = ip46_address_is_ip4 (&face->nat_addr) &&
	     !ip6_address_is_loopback (&face->nat_addr.ip6);

  // hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;

  hicn_ip_address_t temp_addr;
  ip46_address_reset (&(temp_addr.as_ip46));
  hicn_ip_address_t *face_nat_addr = (hicn_ip_address_t *) &face->nat_addr;
  int ret = hicn_interest_rewrite (pkbuf, face_nat_addr, &temp_addr);
  if (ret == HICN_LIB_ERROR_REWRITE_CKSUM_REQUIRED)
    {
      ensure_offload_flags (b0, is_v4);
    }

  ASSERT (face->flags & HICN_FACE_FLAGS_FACE);

  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = face->dpo.dpoi_index;
  *next = face->dpo.dpoi_next_node;
}

static char *hicn4_face_output_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static char *hicn6_face_output_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 next_node;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
} hicn4_face_output_trace_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 next_node;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
} hicn6_face_output_trace_t;

#define TRACE_OUTPUT_PKT_IP4 hicn4_face_output_trace_t
#define TRACE_OUTPUT_PKT_IP6 hicn6_face_output_trace_t

#define face_output_x1(ipv)                                                   \
  do                                                                          \
    {                                                                         \
      vlib_buffer_t *b0;                                                      \
      u32 bi0;                                                                \
      u32 next0 = HICN##ipv##_FACE_OUTPUT_NEXT_ERROR_DROP;                    \
      hicn_face_t *face = NULL;                                               \
                                                                              \
      /* Prefetch for next iteration. */                                      \
      if (n_left_from > 1)                                                    \
	{                                                                     \
	  vlib_buffer_t *b1;                                                  \
	  b1 = vlib_get_buffer (vm, from[1]);                                 \
	  CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, STORE);                   \
	  CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES, STORE);             \
	}                                                                     \
      /* Dequeue a packet buffer */                                           \
      bi0 = from[0];                                                          \
      from += 1;                                                              \
      n_left_from -= 1;                                                       \
      to_next[0] = bi0;                                                       \
      to_next += 1;                                                           \
      n_left_to_next -= 1;                                                    \
                                                                              \
      b0 = vlib_get_buffer (vm, bi0);                                         \
                                                                              \
      hicn_face_id_t face_id = vnet_buffer (b0)->ip.adj_index[VLIB_TX];       \
      if (PREDICT_TRUE (hicn_dpoi_idx_is_valid (face_id)))                    \
	face = hicn_dpoi_get_from_idx (face_id);                              \
                                                                              \
      if (PREDICT_TRUE (face != NULL) && face->flags & HICN_FACE_FLAGS_FACE)  \
	{                                                                     \
	  hicn_face_rewrite_interest (vm, b0, face, &next0);                  \
	  stats.pkts_interest_count += 1;                                     \
	  vlib_increment_combined_counter (                                   \
	    &counters[face_id * HICN_N_COUNTER], thread_index,                \
	    HICN_FACE_COUNTERS_INTEREST_TX, 1,                                \
	    vlib_buffer_length_in_chain (vm, b0));                            \
	}                                                                     \
                                                                              \
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&              \
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))                \
	{                                                                     \
	  TRACE_OUTPUT_PKT_IP##ipv *t =                                       \
	    vlib_add_trace (vm, node, b0, sizeof (*t));                       \
	  t->pkt_type = HICN_PACKET_TYPE_INTEREST;                            \
	  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];            \
	  t->next_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];            \
	  t->next_node = next0;                                               \
	  clib_memcpy_fast (t->packet_data, vlib_buffer_get_current (b0),     \
			    sizeof (t->packet_data));                         \
	}                                                                     \
      if (next0 == HICN##ipv##_FACE_OUTPUT_NEXT_ERROR_DROP)                   \
	{                                                                     \
	  HICN_DEBUG ("Droped!");                                             \
	}                                                                     \
                                                                              \
      /* Verify speculative enqueue, maybe switch current next frame */       \
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,         \
				       n_left_to_next, bi0, next0);           \
    }                                                                         \
  while (0)

#define face_output_x2(ipv)                                                   \
  do                                                                          \
    {                                                                         \
      vlib_buffer_t *b0, *b1;                                                 \
      u32 bi0, bi1;                                                           \
      u32 next0 = HICN##ipv##_FACE_OUTPUT_NEXT_ERROR_DROP;                    \
      u32 next1 = HICN##ipv##_FACE_OUTPUT_NEXT_ERROR_DROP;                    \
      hicn_face_t *face0 = NULL, *face1 = NULL;                               \
                                                                              \
      /* Prefetch for next iteration. */                                      \
      {                                                                       \
	vlib_buffer_t *b2, *b3;                                               \
	b2 = vlib_get_buffer (vm, from[2]);                                   \
	b3 = vlib_get_buffer (vm, from[3]);                                   \
	CLIB_PREFETCH (b2, CLIB_CACHE_LINE_BYTES, STORE);                     \
	CLIB_PREFETCH (b3, CLIB_CACHE_LINE_BYTES, STORE);                     \
	CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES, STORE);               \
	CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES, STORE);               \
      }                                                                       \
      /* Dequeue a packet buffer */                                           \
      bi0 = from[0];                                                          \
      bi1 = from[1];                                                          \
      from += 2;                                                              \
      n_left_from -= 2;                                                       \
      to_next[0] = bi0;                                                       \
      to_next[1] = bi1;                                                       \
      to_next += 2;                                                           \
      n_left_to_next -= 2;                                                    \
                                                                              \
      b0 = vlib_get_buffer (vm, bi0);                                         \
      b1 = vlib_get_buffer (vm, bi1);                                         \
                                                                              \
      hicn_face_id_t face_id0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];      \
      hicn_face_id_t face_id1 = vnet_buffer (b1)->ip.adj_index[VLIB_TX];      \
      if (PREDICT_TRUE (hicn_dpoi_idx_is_valid (face_id0)))                   \
	face0 = hicn_dpoi_get_from_idx (face_id0);                            \
      if (PREDICT_TRUE (hicn_dpoi_idx_is_valid (face_id1)))                   \
	face1 = hicn_dpoi_get_from_idx (face_id1);                            \
                                                                              \
      if (PREDICT_TRUE (face0 != NULL) &&                                     \
	  face0->flags & HICN_FACE_FLAGS_FACE)                                \
	{                                                                     \
	  hicn_face_rewrite_interest (vm, b0, face0, &next0);                 \
	  stats.pkts_interest_count += 1;                                     \
	  vlib_increment_combined_counter (                                   \
	    &counters[face_id0 * HICN_N_COUNTER], thread_index,               \
	    HICN_FACE_COUNTERS_INTEREST_TX, 1,                                \
	    vlib_buffer_length_in_chain (vm, b0));                            \
	}                                                                     \
                                                                              \
      if (PREDICT_TRUE (face1 != NULL) &&                                     \
	  face1->flags & HICN_FACE_FLAGS_FACE)                                \
	{                                                                     \
	  hicn_face_rewrite_interest (vm, b1, face1, &next1);                 \
	  stats.pkts_interest_count += 1;                                     \
	  vlib_increment_combined_counter (                                   \
	    &counters[face_id1 * HICN_N_COUNTER], thread_index,               \
	    HICN_FACE_COUNTERS_INTEREST_TX, 1,                                \
	    vlib_buffer_length_in_chain (vm, b1));                            \
	}                                                                     \
                                                                              \
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&              \
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))                \
	{                                                                     \
	  TRACE_OUTPUT_PKT_IP##ipv *t =                                       \
	    vlib_add_trace (vm, node, b0, sizeof (*t));                       \
	  t->pkt_type = HICN_PACKET_TYPE_INTEREST;                            \
	  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];            \
	  t->next_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];            \
	  t->next_node = next0;                                               \
	  clib_memcpy_fast (t->packet_data, vlib_buffer_get_current (b0),     \
			    sizeof (t->packet_data));                         \
	}                                                                     \
                                                                              \
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&              \
			 (b1->flags & VLIB_BUFFER_IS_TRACED)))                \
	{                                                                     \
	  TRACE_OUTPUT_PKT_IP##ipv *t =                                       \
	    vlib_add_trace (vm, node, b1, sizeof (*t));                       \
	  t->pkt_type = HICN_PACKET_TYPE_INTEREST;                            \
	  t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];            \
	  t->next_index = vnet_buffer (b1)->ip.adj_index[VLIB_TX];            \
	  t->next_node = next1;                                               \
	  clib_memcpy_fast (t->packet_data, vlib_buffer_get_current (b1),     \
			    sizeof (t->packet_data));                         \
	}                                                                     \
      if (next0 == HICN##ipv##_FACE_OUTPUT_NEXT_ERROR_DROP)                   \
	{                                                                     \
	  HICN_DEBUG ("Droped!");                                             \
	}                                                                     \
      if (next1 == HICN##ipv##_FACE_OUTPUT_NEXT_ERROR_DROP)                   \
	{                                                                     \
	  HICN_DEBUG ("Droped!");                                             \
	}                                                                     \
      /* Verify speculative enqueue, maybe switch current next frame */       \
      vlib_validate_buffer_enqueue_x2 (vm, node, next_index, to_next,         \
				       n_left_to_next, bi0, bi1, next0,       \
				       next1);                                \
    }                                                                         \
  while (0)

static uword
hicn4_face_output_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop, X2 */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  face_output_x2 (4);
	}

      /* Dual loop, X1 */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  face_output_x1 (4);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, HICNFWD_ERROR_INTERESTS,
			       stats.pkts_interest_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn4_face_output_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn4_face_output_trace_t *t = va_arg (*args, hicn4_face_output_trace_t *);

  s = format (s,
	      "FACE_IP4_OUTPUT: pkt: %d, sw_if_index %d, next index %d, next "
	      "node: %d\n%U",
	      (int) t->pkt_type, t->sw_if_index, t->next_index, t->next_node,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
VLIB_REGISTER_NODE (hicn4_face_output_node) = {
  .function = hicn4_face_output_node_fn,
  .name = "hicn4-face-output",
  .vector_size = sizeof (u32),
  .format_trace = hicn4_face_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn4_face_output_error_strings),
  .error_strings = hicn4_face_output_error_strings,
  .sibling_of = "ip4-lookup",
};

static uword
hicn6_face_output_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop, X2 */
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  face_output_x2 (6);
	}

      /* Dual loop, X1 */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  face_output_x1 (6);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, HICNFWD_ERROR_INTERESTS,
			       stats.pkts_interest_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn6_face_output_format_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn6_face_output_trace_t *t = va_arg (*args, hicn6_face_output_trace_t *);

  s = format (s,
	      "FACE_IP6_OUTPUT: pkt: %d, sw_if_index %d, next index %d, next "
	      "node: %d\n%U",
	      (int) t->pkt_type, t->sw_if_index, t->next_index, t->next_node,
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
VLIB_REGISTER_NODE (hicn6_face_output_node) = {
  .function = hicn6_face_output_node_fn,
  .name = "hicn6-face-output",
  .vector_size = sizeof (u32),
  .format_trace = hicn6_face_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn6_face_output_error_strings),
  .error_strings = hicn6_face_output_error_strings,
  .sibling_of = "ip6-lookup",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
