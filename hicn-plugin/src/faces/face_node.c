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

#include <vnet/adj/adj.h>

#include "face.h"
#include "face_node.h"
#include "dpo_face.h"
//#include "app/face_prod.h"
#include "../strategy_dpo_manager.h"
#include "face.h"
#include "../cache_policies/cs_lru.h"
#include "../infra.h"
#include "../hicn.h"

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
  u8 packet_data[60];
}
hicn4_face_input_trace_t;

typedef enum
{
  HICN4_FACE_INPUT_NEXT_DATA,
  //HICN4_FACE_INPUT_NEXT_MAPME,
  HICN4_FACE_INPUT_NEXT_ERROR_DROP,
  HICN4_FACE_INPUT_N_NEXT,
} hicn4_face_input_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
}
hicn6_face_input_trace_t;

typedef enum
{
  HICN6_FACE_INPUT_NEXT_DATA,
  //HICN6_FACE_INPUT_NEXT_MAPME,
  HICN6_FACE_INPUT_NEXT_ERROR_DROP,
  HICN6_FACE_INPUT_N_NEXT,
} hicn6_face_input_next_t;

#define NEXT_MAPME_IP4 HICN4_FACE_INPUT_NEXT_ERROR_DROP//HICN4_FACE_INPUT_NEXT_MAPME
#define NEXT_MAPME_IP6 HICN6_FACE_INPUT_NEXT_ERROR_DROP//HICN6_FACE_INPUT_NEXT_MAPME
#define NEXT_DATA_IP4 HICN4_FACE_INPUT_NEXT_DATA
#define NEXT_DATA_IP6 HICN6_FACE_INPUT_NEXT_DATA

#define NEXT_ERROR_DROP_IP4 HICN4_FACE_INPUT_NEXT_ERROR_DROP
#define NEXT_ERROR_DROP_IP6 HICN6_FACE_INPUT_NEXT_ERROR_DROP

#define IP_HEADER_4 ip4_header_t
#define IP_HEADER_6 ip6_header_t

#define LOCK_DPO_FACE_IP4 hicn_dpo_face_ip4_lock
#define LOCK_DPO_FACE_IP6 hicn_dpo_face_ip6_lock

#define TRACE_INPUT_PKT_IP4 hicn4_face_input_trace_t
#define TRACE_INPUT_PKT_IP6 hicn6_face_input_trace_t

/*
 * NOTE: Both hicn4_face_input_node_fn and hicn6_face_input_node_fn
 * present a similar codebase. Macro are hard to debug, although the
 * followind code is pretty straighforward and most of the complexity is in
 * functions that can be easily debug.
 */
#define face_input_x1(ipv)                                              \
  do{                                                                   \
  vlib_buffer_t *b0;                                                    \
  u32 bi0;                                                              \
  u32 next0 = NEXT_ERROR_DROP_IP##ipv;                                  \
  IP_HEADER_##ipv * ip_hdr = NULL;                                      \
  hicn_buffer_t * hicnb0;                                               \
  int ret;                                                              \
  /* Prefetch for next iteration. */                                    \
  if (n_left_from > 1)                                                  \
    {                                                                   \
      vlib_buffer_t *b1;                                                \
      b1 = vlib_get_buffer (vm, from[1]);                               \
      CLIB_PREFETCH (b1, 2*CLIB_CACHE_LINE_BYTES, STORE);               \
      CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES , LOAD);           \
    }                                                                   \
  /* Dequeue a packet buffer */                                         \
  bi0 = from[0];                                                        \
  from += 1;                                                            \
  n_left_from -= 1;                                                     \
  to_next[0] = bi0;                                                     \
  to_next += 1;                                                         \
  n_left_to_next -= 1;                                                  \
                                                                        \
  b0 = vlib_get_buffer (vm, bi0);                                       \
  hicnb0 = hicn_get_buffer(b0);                                         \
  ip_hdr = (IP_HEADER_##ipv *) vlib_buffer_get_current(b0);             \
                                                                        \
  u8 is_icmp = ip_hdr->protocol == IPPROTO_ICMPV##ipv;                  \
                                                                        \
  next0 = is_icmp*NEXT_MAPME_IP##ipv +                                  \
    (1-is_icmp)*NEXT_DATA_IP##ipv;                                      \
                                                                        \
  ret = LOCK_DPO_FACE_IP##ipv                                           \
    (&(hicnb0->face_id),                                                \
     &(hicnb0->in_faces_vec_id),                                        \
     &hicnb0->flags,                                                    \
     &(ip_hdr->dst_address));                                           \
                                                                        \
  if ( PREDICT_FALSE(ret != HICN_ERROR_NONE) )                          \
    next0 = NEXT_ERROR_DROP_IP##ipv;                                    \
  else                                                                  \
    {                                                                   \
      vlib_increment_combined_counter (                                 \
                                       &counters[hicnb0->face_id        \
                                       * HICN_N_COUNTER], thread_index, \
                               HICN_FACE_COUNTERS_DATA_RX,              \
                               1,                                       \
                               vlib_buffer_length_in_chain(vm, b0));    \
      stats.pkts_data_count += 1;                                       \
    }                                                                   \
                                                                        \
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&            \
                     (b0->flags & VLIB_BUFFER_IS_TRACED)))              \
    {                                                                   \
      TRACE_INPUT_PKT_IP##ipv *t =                                      \
        vlib_add_trace (vm, node, b0, sizeof (*t));                     \
      t->pkt_type = HICN_PKT_TYPE_INTEREST;                             \
      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];          \
      t->next_index = next0;                                            \
      clib_memcpy_fast (t->packet_data,					\
			vlib_buffer_get_current (b0),			\
			sizeof (t->packet_data));			\
    }                                                                   \
                                                                        \
                                                                        \
  /* Verify speculative enqueue, maybe switch current next frame */     \
  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,                \
                                   to_next, n_left_to_next,             \
                                   bi0, next0);                         \
  }while(0)


#define face_input_x2(ipv)                                              \
  do{                                                                   \
    vlib_buffer_t *b0, *b1;                                             \
    u32 bi0, bi1;                                                       \
    u32 next0 = NEXT_ERROR_DROP_IP##ipv;                                \
    u32 next1 = NEXT_ERROR_DROP_IP##ipv;                                \
    IP_HEADER_##ipv * ip_hdr0 = NULL;                                   \
    IP_HEADER_##ipv * ip_hdr1 = NULL;                                   \
    hicn_buffer_t * hicnb0;                                             \
    hicn_buffer_t * hicnb1;                                             \
    int ret0, ret1;                                                     \
    /* Prefetch for next iteration. */                                  \
    {                                                                   \
      vlib_buffer_t *b2, *b3;                                           \
      b2 = vlib_get_buffer (vm, from[2]);                               \
      b3 = vlib_get_buffer (vm, from[3]);                               \
      CLIB_PREFETCH (b2, 2*CLIB_CACHE_LINE_BYTES, STORE);		\
      CLIB_PREFETCH (b3, 2*CLIB_CACHE_LINE_BYTES, STORE);		\
      CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES , LOAD);           \
      CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES , LOAD);           \
    }                                                                   \
    /* Dequeue a packet buffer */                                       \
    bi0 = from[0];                                                      \
    bi1 = from[1];                                                      \
    from += 2;                                                          \
    n_left_from -= 2;                                                   \
    to_next[0] = bi0;                                                   \
    to_next[1] = bi1;                                                   \
    to_next += 2;                                                       \
    n_left_to_next -= 2;                                                \
                                                                        \
    b0 = vlib_get_buffer (vm, bi0);                                     \
    b1 = vlib_get_buffer (vm, bi1);                                     \
    hicnb0 = hicn_get_buffer(b0);                                       \
    hicnb1 = hicn_get_buffer(b1);                                       \
    ip_hdr0 = (IP_HEADER_##ipv *) vlib_buffer_get_current(b0);          \
    ip_hdr1 = (IP_HEADER_##ipv *) vlib_buffer_get_current(b1);          \
                                                                        \
    u8 is_icmp0 = ip_hdr0->protocol == IPPROTO_ICMPV##ipv;              \
    u8 is_icmp1 = ip_hdr1->protocol == IPPROTO_ICMPV##ipv;              \
                                                                        \
    next0 = is_icmp0*NEXT_MAPME_IP##ipv +                               \
      (1-is_icmp0)*NEXT_DATA_IP##ipv;                                   \
                                                                        \
    next1 = is_icmp1*NEXT_MAPME_IP##ipv +                               \
      (1-is_icmp1)*NEXT_DATA_IP##ipv;                                   \
                                                                        \
                                                                        \
    ret0 = LOCK_DPO_FACE_IP##ipv                                        \
      (&(hicnb0->face_id),                                              \
       &(hicnb0->in_faces_vec_id),                                      \
       &hicnb0->flags,                                                  \
       &(ip_hdr0->dst_address));                                        \
                                                                        \
    ret1 = LOCK_DPO_FACE_IP##ipv                                        \
      (&(hicnb1->face_id),                                              \
       &(hicnb1->in_faces_vec_id),                                      \
       &hicnb1->flags,                                                  \
       &(ip_hdr1->dst_address));                                        \
                                                                        \
    if ( PREDICT_FALSE(ret0 != HICN_ERROR_NONE) )                       \
      next0 = NEXT_ERROR_DROP_IP##ipv;                                  \
    else                                                                \
      {                                                                 \
        vlib_increment_combined_counter (                               \
                                         &counters[hicnb0->face_id      \
                                       * HICN_N_COUNTER], thread_index, \
                             HICN_FACE_COUNTERS_DATA_RX,                \
                             1,                                         \
                             vlib_buffer_length_in_chain(vm, b0));      \
        stats.pkts_data_count += 1;                                     \
      }                                                                 \
                                                                        \
    if ( PREDICT_FALSE(ret1 != HICN_ERROR_NONE) )                       \
      next1 = NEXT_ERROR_DROP_IP##ipv;                                  \
    else                                                                \
      {                                                                 \
        vlib_increment_combined_counter (                               \
                                         &counters[hicnb1->face_id      \
                                        * HICN_N_COUNTER], thread_index,\
                              HICN_FACE_COUNTERS_DATA_RX,               \
                              1,                                        \
                              vlib_buffer_length_in_chain(vm, b1));     \
        stats.pkts_data_count += 1;                                     \
      }                                                                 \
                                                                        \
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&            \
                     (b0->flags & VLIB_BUFFER_IS_TRACED)))              \
    {                                                                   \
      TRACE_INPUT_PKT_IP##ipv *t =                                      \
        vlib_add_trace (vm, node, b0, sizeof (*t));                     \
      t->pkt_type = HICN_PKT_TYPE_INTEREST;                             \
      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];          \
      t->next_index = next0;                                            \
      clib_memcpy_fast (t->packet_data,					\
			vlib_buffer_get_current (b0),			\
			sizeof (t->packet_data));			\
    }                                                                   \
                                                                        \
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&            \
                     (b1->flags & VLIB_BUFFER_IS_TRACED)))              \
    {                                                                   \
      TRACE_INPUT_PKT_IP##ipv *t =                                      \
        vlib_add_trace (vm, node, b1, sizeof (*t));                     \
      t->pkt_type = HICN_PKT_TYPE_INTEREST;                             \
      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];          \
      t->next_index = next1;                                            \
      clib_memcpy_fast (t->packet_data,					\
			vlib_buffer_get_current (b1),			\
			sizeof (t->packet_data));			\
    }                                                                   \
                                                                        \
                                                                        \
  /* Verify speculative enqueue, maybe switch current next frame */     \
  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,                \
                                   to_next, n_left_to_next,             \
                                   bi0, bi1, next0, next1);             \
  }while(0)


static uword
hicn4_face_input_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                          vlib_frame_t * frame)
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

  vlib_node_increment_counter (vm, node->node_index,
			       HICNFWD_ERROR_DATAS, stats.pkts_data_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn4_face_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn4_face_input_trace_t *t =
    va_arg (*args, hicn4_face_input_trace_t *);

  s = format (s, "FACE_IP4_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	      (int) t->pkt_type, t->sw_if_index, t->next_index,
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}


/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
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
    //[HICN4_FACE_INPUT_NEXT_MAPME] = "hicn-mapme-ack",
    [HICN4_FACE_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/**
 * @brief IPv6 face input node function
 * @see hicn6_face_input_node_fn
 */
static uword
hicn6_face_input_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame)
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

  vlib_node_increment_counter (vm, node->node_index,
			       HICNFWD_ERROR_DATAS, stats.pkts_data_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn6_face_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn6_face_input_trace_t *t =
    va_arg (*args, hicn6_face_input_trace_t *);

  s = format (s, "FACE_IP6_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	      (int) t->pkt_type, t->sw_if_index, t->next_index,
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
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
    //[HICN6_FACE_INPUT_NEXT_MAPME] = "hicn-mapme-ack",
    [HICN6_FACE_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/**** FACE OUTPUT *****/

typedef enum
{
  HICN4_FACE_OUTPUT_NEXT_ECHO_REPLY,
  HICN4_FACE_OUTPUT_N_NEXT,
} hicn4_face_output_next_t;

typedef enum
{
  HICN6_FACE_OUTPUT_NEXT_ECHO_REPLY,
  HICN6_FACE_OUTPUT_N_NEXT,
} hicn6_face_output_next_t;

/* static_always_inline void */
/* hicn_reply_probe_v4 (vlib_buffer_t * b, hicn_face_t * face) */
/* { */
/*   hicn_header_t *h0 = vlib_buffer_get_current (b); */
/*   hicn_face_ip_t * face_ip = (hicn_face_ip_t *)(&face->data); */
/*   h0->v4.ip.saddr = h0->v4.ip.daddr; */
/*   h0->v4.ip.daddr = face_ip->local_addr.ip4; */
/*   vnet_buffer (b)->sw_if_index[VLIB_RX] = face->shared.sw_if; */

/*   u16 * dst_port_ptr = (u16 *)(((u8*)h0) + sizeof(ip4_header_t) + sizeof(u16)); */
/*   u16 dst_port = *dst_port_ptr; */
/*   u16 * src_port_ptr = (u16 *)(((u8*)h0) + sizeof(ip4_header_t)); */

/*   *dst_port_ptr = *src_port_ptr; */
/*   *src_port_ptr = dst_port; */

/*   hicn_type_t type = hicn_get_buffer (b)->type; */
/*   hicn_ops_vft[type.l1]->set_lifetime (type, &h0->protocol, 0); */
/* } */

/* static_always_inline void */
/* hicn_reply_probe_v6 (vlib_buffer_t * b, hicn_face_t * face) */
/* { */
/*   hicn_header_t *h0 = vlib_buffer_get_current (b); */
/*   hicn_face_ip_t * face_ip = (hicn_face_ip_t *)(&face->data); */
/*   h0->v6.ip.saddr = h0->v6.ip.daddr; */
/*   h0->v6.ip.daddr = face_ip->local_addr.ip6; */
/*   vnet_buffer (b)->sw_if_index[VLIB_RX] = face->shared.sw_if; */

/*   u16 * dst_port_ptr = (u16 *)(((u8*)h0) + sizeof(ip6_header_t) + sizeof(u16)); */
/*   u16 dst_port = *dst_port_ptr; */
/*   u16 * src_port_ptr = (u16 *)(((u8*)h0) + sizeof(ip6_header_t)); */

/*   *dst_port_ptr = *src_port_ptr; */
/*   *src_port_ptr = dst_port; */

/*   hicn_type_t type = hicn_get_buffer (b)->type; */
/*   hicn_ops_vft[type.l1]->set_lifetime (type, &h0->protocol, 0); */

/* } */

/* static_always_inline u32 */
/* hicn_face_match_probe (vlib_buffer_t * b, hicn_face_t * face, u32 * next) */
/* { */

/*   u8 *ptr = vlib_buffer_get_current (b); */
/*   u8 v = *ptr & 0xf0; */
/*   u8 res = 0; */

/*   if ( v == 0x40 ) */
/*     { */
/*       u16 * dst_port = (u16 *)(ptr + sizeof(ip4_header_t) + sizeof(u16)); */
/*       if (*dst_port == clib_net_to_host_u16(DEFAULT_PROBING_PORT)) */
/*         { */
/*           hicn_reply_probe_v6(b, face); */
/*           *next = HICN4_FACE_NEXT_ECHO_REPLY; */
/*           res = 1; */
/*         } */
/*     } */
/*   else if ( v == 0x60 ) */
/*     { */
/*       u16 * dst_port = (u16 *)(ptr + sizeof(ip6_header_t) + sizeof(u16)); */
/*       if (*dst_port == clib_net_to_host_u16(DEFAULT_PROBING_PORT)) */
/*         { */
/*           hicn_reply_probe_v6(b, face); */
/*           *next = HICN6_FACE_NEXT_ECHO_REPLY; */
/*           res = 1; */
/*         } */
/*     } */
/*   return res; */
/* } */


static inline void
hicn_face_rewrite_interest (vlib_main_t * vm, vlib_buffer_t * b0,
			    hicn_face_t * face, u32 * next)
{

  /* if ((face->flags & HICN_FACE_FLAGS_APPFACE_PROD) && hicn_face_match_probe(b0, face, next)) */
  /*   return; */

  hicn_header_t *hicn = vlib_buffer_get_current (b0);

  //hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;

  ip46_address_t temp_addr;
  ip46_address_reset (&temp_addr);
  hicn_type_t type = hicn_get_buffer (b0)->type;
  hicn_ops_vft[type.l1]->rewrite_interest (type, &hicn->protocol,
					   &face->nat_addr, &temp_addr);

  if (ip46_address_is_ip4(&face->nat_addr))
    b0->flags |= VNET_BUFFER_F_OFFLOAD_IP_CKSUM;

  b0->flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;

  ASSERT(face->flags & HICN_FACE_FLAGS_FACE);

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
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
}
hicn4_face_output_trace_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
}
hicn6_face_output_trace_t;

#define TRACE_OUTPUT_PKT_IP4 hicn4_face_output_trace_t
#define TRACE_OUTPUT_PKT_IP6 hicn6_face_output_trace_t

#define face_output_x1(ipv)                                         \
  do {                                                              \
    vlib_buffer_t *b0;                                              \
    u32 bi0;                                                        \
    u32 next0 = IP_LOOKUP_NEXT_DROP;				    \
    hicn_face_t * face;                                             \
                                                                    \
    /* Prefetch for next iteration. */                              \
    if (n_left_from > 1)                                            \
      {                                                             \
        vlib_buffer_t *b1;                                          \
        b1 = vlib_get_buffer (vm, from[1]);                         \
        CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, STORE);	    \
        CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES , STORE);    \
      }                                                             \
    /* Dequeue a packet buffer */                                   \
    bi0 = from[0];                                                  \
    from += 1;                                                      \
    n_left_from -= 1;                                               \
    to_next[0] = bi0;                                               \
    to_next += 1;                                                   \
    n_left_to_next -= 1;                                            \
                                                                    \
    b0 = vlib_get_buffer (vm, bi0);                                 \
                                                                    \
    hicn_face_id_t face_id = vnet_buffer (b0)->ip.adj_index[VLIB_TX];   \
    face =                                                              \
      hicn_dpoi_get_from_idx (face_id);                                 \
                                                                        \
    if (PREDICT_TRUE(face != NULL))                                     \
      {                                                                 \
        hicn_face_rewrite_interest					\
          (vm, b0, face, &next0);					\
	stats.pkts_interest_count += 1;					\
        vlib_increment_combined_counter (                               \
                                  &counters[face_id * HICN_N_COUNTER],  \
                                  thread_index,                         \
                                  HICN_FACE_COUNTERS_INTEREST_TX,       \
                                  1,                                    \
                                  vlib_buffer_length_in_chain(vm, b0)); \
      }                                                                 \
                                                                        \
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&          \
                       (b0->flags & VLIB_BUFFER_IS_TRACED)))            \
      {                                                                 \
        TRACE_OUTPUT_PKT_IP##ipv *t =                                   \
          vlib_add_trace (vm, node, b0, sizeof (*t));                   \
        t->pkt_type = HICN_PKT_TYPE_INTEREST;                           \
        t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];        \
        t->next_index = next0;                                          \
	clib_memcpy_fast (t->packet_data,				\
			vlib_buffer_get_current (b0),			\
			sizeof (t->packet_data));			\
      }                                                                 \
                                                                        \
                                                                        \
    /* Verify speculative enqueue, maybe switch current next frame */   \
    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,              \
                                     to_next, n_left_to_next,           \
                                     bi0, next0);                       \
  }while(0)

#define face_output_x2(ipv)                                         \
  do {                                                              \
    vlib_buffer_t *b0, *b1;                                         \
    u32 bi0, bi1;                                                   \
    u32 next0 = IP_LOOKUP_NEXT_DROP;				    \
    u32 next1 = IP_LOOKUP_NEXT_DROP;				    \
    hicn_face_t *face0, *face1;                                     \
                                                                    \
    /* Prefetch for next iteration. */                              \
    {                                                               \
      vlib_buffer_t *b2, *b3;                                       \
      b2 = vlib_get_buffer (vm, from[2]);                           \
      b3 = vlib_get_buffer (vm, from[3]);                           \
      CLIB_PREFETCH (b2, CLIB_CACHE_LINE_BYTES, STORE);             \
      CLIB_PREFETCH (b3, CLIB_CACHE_LINE_BYTES, STORE);             \
      CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES , STORE);      \
      CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES , STORE);      \
    }                                                               \
  /* Dequeue a packet buffer */                                     \
    bi0 = from[0];                                                  \
    bi1 = from[1];                                                  \
    from += 2;                                                      \
    n_left_from -= 2;                                               \
    to_next[0] = bi0;                                               \
    to_next[1] = bi1;                                               \
    to_next += 2;                                                   \
    n_left_to_next -= 2;                                            \
                                                                    \
    b0 = vlib_get_buffer (vm, bi0);                                 \
    b1 = vlib_get_buffer (vm, bi1);                                 \
                                                                    \
    hicn_face_id_t face_id0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];  \
    hicn_face_id_t face_id1 = vnet_buffer (b1)->ip.adj_index[VLIB_TX];  \
    face0 =                                                             \
      hicn_dpoi_get_from_idx (face_id0);                                \
    face1 =                                                             \
      hicn_dpoi_get_from_idx (face_id1);                                \
                                                                        \
    if (PREDICT_TRUE(face0 != NULL))                                    \
      {                                                                 \
        hicn_face_rewrite_interest					\
          (vm, b0, face0, &next0);					\
	stats.pkts_interest_count += 1;					\
        vlib_increment_combined_counter (                               \
                                  &counters[face_id0 * HICN_N_COUNTER], \
                                  thread_index,                         \
                                  HICN_FACE_COUNTERS_INTEREST_TX,       \
                                  1,                                    \
                                  vlib_buffer_length_in_chain(vm, b0)); \
      }                                                                 \
                                                                        \
    if (PREDICT_TRUE(face1 != NULL))                                    \
      {                                                                 \
        hicn_face_rewrite_interest					\
          (vm, b1, face1, &next1);					\
	stats.pkts_interest_count += 1;					\
        vlib_increment_combined_counter (                               \
                                  &counters[face_id1 * HICN_N_COUNTER], \
                                  thread_index,                         \
                                  HICN_FACE_COUNTERS_INTEREST_TX,       \
                                  1,                                    \
                                  vlib_buffer_length_in_chain(vm, b1)); \
      }                                                                 \
                                                                        \
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&            \
                     (b0->flags & VLIB_BUFFER_IS_TRACED)))              \
    {                                                                   \
      TRACE_OUTPUT_PKT_IP##ipv *t =                                     \
        vlib_add_trace (vm, node, b0, sizeof (*t));                     \
      t->pkt_type = HICN_PKT_TYPE_INTEREST;                             \
      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];          \
      t->next_index = next0;                                            \
      clib_memcpy_fast (t->packet_data,					\
			vlib_buffer_get_current (b0),			\
			sizeof (t->packet_data));			\
    }                                                                   \
                                                                        \
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&            \
                     (b1->flags & VLIB_BUFFER_IS_TRACED)))              \
    {                                                                   \
      TRACE_OUTPUT_PKT_IP##ipv *t =                                     \
        vlib_add_trace (vm, node, b1, sizeof (*t));                     \
      t->pkt_type = HICN_PKT_TYPE_INTEREST;                             \
      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];          \
      t->next_index = next1;                                            \
      clib_memcpy_fast (t->packet_data,					\
			vlib_buffer_get_current (b1),			\
			sizeof (t->packet_data));			\
    }                                                                   \
                                                                        \
                                                                        \
  /* Verify speculative enqueue, maybe switch current next frame */     \
  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,                \
                                   to_next, n_left_to_next,             \
                                   bi0, bi1, next0, next1);             \
  }while(0)


static uword
hicn4_face_output_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
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

  vlib_node_increment_counter (vm, node->node_index,
			       HICNFWD_ERROR_INTERESTS,
			       stats.pkts_interest_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn4_face_output_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn4_face_output_trace_t *t =
    va_arg (*args, hicn4_face_output_trace_t *);

  s =
    format (s, "FACE_IP4_OUTPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	    (int) t->pkt_type, t->sw_if_index, t->next_index,
	    format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn4_face_output_node) =
{
  .function = hicn4_face_output_node_fn,
  .name = "hicn4-face-output",
  .vector_size = sizeof(u32),
  .format_trace = hicn4_face_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn4_face_output_error_strings),
  .error_strings = hicn4_face_output_error_strings,
  .n_next_nodes = HICN4_FACE_OUTPUT_N_NEXT,
  /* Reusing the list of nodes from lookup to be compatible with arp */
  .next_nodes =
  {
   [HICN4_FACE_OUTPUT_NEXT_ECHO_REPLY] = "hicn4-face-input",
  }
};
/* *INDENT-ON* */


static uword
hicn6_face_output_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
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

  vlib_node_increment_counter (vm, node->node_index,
			       HICNFWD_ERROR_INTERESTS,
			       stats.pkts_interest_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn6_face_output_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn6_face_output_trace_t *t =
    va_arg (*args, hicn6_face_output_trace_t *);

  s =
    format (s, "FACE_IP6_OUTPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	    (int) t->pkt_type, t->sw_if_index, t->next_index,
	    format_ip6_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn6_face_output_node) =
{
  .function = hicn6_face_output_node_fn,
  .name = "hicn6-face-output",
  .vector_size = sizeof(u32),
  .format_trace = hicn6_face_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicn6_face_output_error_strings),
  .error_strings = hicn6_face_output_error_strings,
  .n_next_nodes = HICN6_FACE_OUTPUT_N_NEXT,
  /* Reusing the list of nodes from lookup to be compatible with neighbour discovery */
  .next_nodes =
  {
   [HICN6_FACE_OUTPUT_NEXT_ECHO_REPLY] = "hicn6-face-input"
  }
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
