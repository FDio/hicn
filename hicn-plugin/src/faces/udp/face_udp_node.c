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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip_packet.h>

#include "face_udp.h"
#include "face_udp_node.h"
#include "dpo_udp.h"
#include "../face.h"
#include "../../strategy.h"
#include "../../strategy_dpo_manager.h"
#include "../../hicn.h"

/**
 * @File
 *
 * Definition of the nodes for udp faces.
 */

vlib_node_registration_t hicn_face_udp4_input_node;
vlib_node_registration_t hicn_face_udp6_input_node;
vlib_node_registration_t hicn_face_udp4_output_node;
vlib_node_registration_t hicn_face_udp6_output_node;

static char *hicn_face_udp4_input_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static char *hicn_face_udp6_input_error_strings[] = {
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
hicn_face_udp4_input_trace_t;

typedef enum
{
  HICN_FACE_UDP4_INPUT_NEXT_DATA,
  HICN_FACE_UDP4_INPUT_NEXT_MAPME,
  HICN_FACE_UDP4_INPUT_NEXT_ERROR_DROP,
  HICN_FACE_UDP4_INPUT_N_NEXT,
} hicn_face_udp4_input_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
}
hicn_face_udp6_input_trace_t;

typedef enum
{
  HICN_FACE_UDP6_INPUT_NEXT_DATA,
  HICN_FACE_UDP6_INPUT_NEXT_MAPME,
  HICN_FACE_UDP6_INPUT_NEXT_ERROR_DROP,
  HICN_FACE_UDP6_INPUT_N_NEXT,
} hicn_face_udp6_input_next_t;

#define ERROR_INPUT_UDP4 HICN_FACE_UDP4_INPUT_NEXT_ERROR_DROP
#define ERROR_INPUT_UDP6 HICN_FACE_UDP6_INPUT_NEXT_ERROR_DROP

#define NEXT_MAPME_UDP4 HICN_FACE_UDP4_INPUT_NEXT_MAPME
#define NEXT_MAPME_UDP6 HICN_FACE_UDP6_INPUT_NEXT_MAPME
#define NEXT_DATA_UDP4 HICN_FACE_UDP4_INPUT_NEXT_DATA
#define NEXT_DATA_UDP6 HICN_FACE_UDP6_INPUT_NEXT_DATA

#define IP_HEADER_4 ip4_header_t
#define IP_HEADER_6 ip6_header_t

#define HICN_DPO_UDP_LOCK_IP4 hicn_dpo_udp4_lock
#define HICN_DPO_UDP_LOCK_IP6 hicn_dpo_udp6_lock

#define TRACE_INPUT_PKT_UDP4 hicn_face_udp4_input_trace_t
#define TRACE_INPUT_PKT_UDP6 hicn_face_udp6_input_trace_t

#define SIZE_HICN_HEADER4 sizeof(ip4_header_t) + sizeof(udp_header_t)
#define SIZE_HICN_HEADER6 sizeof(ip6_header_t) + sizeof(udp_header_t)


#define face_input_x1(ipv)                                          \
  do {                                                              \
    int ret;                                                        \
    vlib_buffer_t *b0;                                              \
    u32 bi0;                                                        \
    u32 next0 = ERROR_INPUT_UDP##ipv;                               \
    IP_HEADER_##ipv * ip_hdr = NULL;                                \
    u8 * inner_ip_hdr = NULL;					    \
    udp_header_t * udp_hdr = NULL;                                  \
    hicn_buffer_t * hicnb0;                                         \
    /* Prefetch for next iteration. */                              \
    if (n_left_from > 1)                                            \
      {                                                             \
        vlib_buffer_t *b1;                                          \
        b1 = vlib_get_buffer (vm, from[1]);                         \
        CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, STORE);           \
        CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES , LOAD);     \
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
    ip_hdr = (IP_HEADER_##ipv *) vlib_buffer_get_current(b0);       \
    udp_hdr = (udp_header_t *) (ip_hdr + 1);                        \
    hicnb0 = hicn_get_buffer(b0);                                   \
								    \
    inner_ip_hdr = (u8 *)(udp_hdr + 1);				    \
    u8 is_v6 = hicn_is_v6((hicn_header_t *)inner_ip_hdr);           \
    u8 is_icmp = is_v6*(inner_ip_hdr[6] == IPPROTO_ICMPV6) +	    \
      (1 - is_v6)*(inner_ip_hdr[9] == IPPROTO_ICMPV4);		    \
                                                                    \
    ret = HICN_DPO_UDP_LOCK_IP##ipv                                 \
      (&(hicnb0->face_dpo_id),                                      \
       &(ip_hdr->dst_address),                                      \
       &(ip_hdr->src_address),                                      \
       (udp_hdr->dst_port),                                         \
       (udp_hdr->src_port),                                         \
       &hicnb0->flags);                                             \
                                                                    \
    if ( PREDICT_FALSE(ret != HICN_ERROR_NONE) )                    \
      {                                                             \
        next0 = ERROR_INPUT_UDP##ipv;                               \
      }                                                             \
    else                                                            \
      {                                                             \
	next0 = is_icmp*NEXT_MAPME_UDP##ipv +			    \
	  (1-is_icmp)*NEXT_DATA_UDP##ipv;			    \
	stats.pkts_data_count += 1;				    \
								    \
        vlib_buffer_advance(b0, sizeof(IP_HEADER_##ipv) +           \
                            sizeof(udp_header_t));                  \
        vlib_increment_combined_counter (                           \
                           &counters[hicnb0->face_dpo_id.dpoi_index \
                                  * HICN_N_COUNTER], thread_index,  \
                           HICN_FACE_COUNTERS_DATA_RX,              \
                           1,                                       \
                           vlib_buffer_length_in_chain(vm, b0));    \
      }                                                             \
								    \
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&	    \
                       (b0->flags & VLIB_BUFFER_IS_TRACED)))        \
      {                                                             \
        TRACE_INPUT_PKT_UDP##ipv *t =                               \
          vlib_add_trace (vm, node, b0, sizeof (*t));               \
        t->pkt_type = HICN_PKT_TYPE_CONTENT;                        \
        t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];    \
        t->next_index = next0;                                      \
	clib_memcpy_fast (t->packet_data,			    \
			  vlib_buffer_get_current (b0),		    \
			  sizeof (t->packet_data));		    \
      }								    \
								    \
                                                                    \
    /* Verify speculative enqueue, maybe switch current next frame */   \
    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,              \
                                     to_next, n_left_to_next,           \
                                     bi0, next0);                       \
  }while(0)                                                             \

#define face_input_x2(ipv)                                          \
  do {                                                              \
    int ret0, ret1;                                                 \
    vlib_buffer_t *b0, *b1;                                         \
    u32 bi0, bi1;                                                   \
    u32 next0 = ERROR_INPUT_UDP##ipv;                               \
    u32 next1 = ERROR_INPUT_UDP##ipv;                               \
    IP_HEADER_##ipv * ip_hdr0 = NULL;                               \
    IP_HEADER_##ipv * ip_hdr1 = NULL;                               \
    u8 * inner_ip_hdr0 = NULL;					    \
    u8 * inner_ip_hdr1 = NULL;					    \
    udp_header_t * udp_hdr0 = NULL;                                 \
    udp_header_t * udp_hdr1 = NULL;                                 \
    hicn_buffer_t *hicnb0, *hicnb1;                                 \
                                                                    \
    /* Prefetch for next iteration. */                              \
    {                                                               \
      vlib_buffer_t *b2, *b3;                                       \
      b2 = vlib_get_buffer (vm, from[2]);                           \
      b3 = vlib_get_buffer (vm, from[3]);                           \
      CLIB_PREFETCH (b2, CLIB_CACHE_LINE_BYTES, STORE);             \
      CLIB_PREFETCH (b3, CLIB_CACHE_LINE_BYTES, STORE);             \
      CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES , LOAD);       \
      CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES , LOAD);       \
    }                                                               \
                                                                    \
    /* Dequeue a packet buffer */                                   \
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
    ip_hdr0 = (IP_HEADER_##ipv *) vlib_buffer_get_current(b0);      \
    ip_hdr1 = (IP_HEADER_##ipv *) vlib_buffer_get_current(b1);      \
    udp_hdr0 = (udp_header_t *) (ip_hdr0 + 1);                      \
    udp_hdr1 = (udp_header_t *) (ip_hdr1 + 1);                      \
    hicnb0 = hicn_get_buffer(b0);                                   \
    hicnb1 = hicn_get_buffer(b1);                                   \
                                                                    \
    inner_ip_hdr0 = (u8 *)(udp_hdr0 + 1);			    \
    u8 is_v6_0 = hicn_is_v6((hicn_header_t *)inner_ip_hdr0);        \
     u8 is_icmp0 = is_v6_0*(inner_ip_hdr0[6] == IPPROTO_ICMPV6) +   \
      (1 - is_v6_0)*(inner_ip_hdr0[9] == IPPROTO_ICMPV4);	    \
								    \
    inner_ip_hdr1 = (u8 *)(udp_hdr1 + 1);			    \
    u8 is_v6_1 = hicn_is_v6((hicn_header_t *)inner_ip_hdr1);        \
    u8 is_icmp1 = is_v6_1*(inner_ip_hdr1[6] == IPPROTO_ICMPV6) +    \
      (1 - is_v6_1)*(inner_ip_hdr1[9] == IPPROTO_ICMPV4);	    \
								    \
    ret0 = HICN_DPO_UDP_LOCK_IP##ipv                                \
      (&(hicnb0->face_dpo_id),                                      \
       &(ip_hdr0->dst_address),                                     \
       &(ip_hdr0->src_address),                                     \
       (udp_hdr0->dst_port),                                        \
       (udp_hdr0->src_port),                                        \
       &hicnb0->flags);                                             \
                                                                    \
    ret1 = HICN_DPO_UDP_LOCK_IP##ipv                                \
      (&(hicnb1->face_dpo_id),                                      \
       &(ip_hdr1->dst_address),                                     \
       &(ip_hdr1->src_address),                                     \
       (udp_hdr1->dst_port),                                        \
       (udp_hdr1->src_port),                                        \
       &hicnb1->flags);                                             \
								    \
    if ( PREDICT_FALSE(ret0 != HICN_ERROR_NONE) )                   \
      {                                                             \
        next0 = ERROR_INPUT_UDP##ipv;                               \
      }                                                             \
    else                                                            \
      {                                                             \
	stats.pkts_data_count += 1;				    \
	next0 = is_icmp0*NEXT_MAPME_UDP##ipv +			    \
	  (1-is_icmp0)*NEXT_DATA_UDP##ipv;			    \
								    \
        vlib_buffer_advance(b0, sizeof(IP_HEADER_##ipv) +           \
                            sizeof(udp_header_t));                  \
        vlib_increment_combined_counter (                           \
                        &counters[hicnb0->face_dpo_id.dpoi_index    \
                                  * HICN_N_COUNTER], thread_index,  \
                        HICN_FACE_COUNTERS_DATA_RX,                 \
                        1,                                          \
                        vlib_buffer_length_in_chain(vm, b0));       \
      }                                                             \
                                                                    \
    if ( PREDICT_FALSE(ret1 != HICN_ERROR_NONE) )                   \
      {                                                             \
        next1 = ERROR_INPUT_UDP##ipv;                               \
      }                                                             \
    else                                                            \
      {                                                             \
	stats.pkts_data_count += 1;				    \
	next1 = is_icmp1*NEXT_MAPME_UDP##ipv +			    \
	  (1-is_icmp1)*NEXT_DATA_UDP##ipv;			    \
								    \
        vlib_buffer_advance(b1, sizeof(IP_HEADER_##ipv) +           \
                            sizeof(udp_header_t));                  \
        vlib_increment_combined_counter (                           \
                          &counters[hicnb1->face_dpo_id.dpoi_index  \
                                    * HICN_N_COUNTER], thread_index,\
                          HICN_FACE_COUNTERS_DATA_RX,               \
                          1,                                        \
                          vlib_buffer_length_in_chain(vm, b1));     \
      }                                                             \
                                                                    \
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&      \
                       (b0->flags & VLIB_BUFFER_IS_TRACED)))        \
      {                                                             \
        TRACE_INPUT_PKT_UDP##ipv *t =                               \
          vlib_add_trace (vm, node, b0, sizeof (*t));               \
        t->pkt_type = HICN_PKT_TYPE_CONTENT;                        \
        t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];    \
        t->next_index = next0;                                      \
	clib_memcpy_fast (t->packet_data,			    \
			  vlib_buffer_get_current (b0),		    \
			  sizeof (t->packet_data));		    \
      }                                                             \
                                                                    \
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&      \
                       (b1->flags & VLIB_BUFFER_IS_TRACED)))        \
      {                                                             \
        TRACE_INPUT_PKT_UDP##ipv *t =                               \
          vlib_add_trace (vm, node, b1, sizeof (*t));               \
        t->pkt_type = HICN_PKT_TYPE_CONTENT;                        \
        t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];    \
        t->next_index = next1;                                      \
	clib_memcpy_fast (t->packet_data,			    \
			  vlib_buffer_get_current (b1),		    \
			  sizeof (t->packet_data));		    \
      }                                                             \
                                                                    \
                                                                    \
    /* Verify speculative enqueue, maybe switch current next frame */   \
    vlib_validate_buffer_enqueue_x2 (vm, node, next_index,              \
                                     to_next, n_left_to_next,           \
                                     bi0, bi1, next0, next1);           \
  }while(0)                                                             \

static uword
hicn_face_udp4_input_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
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
hicn_face_udp4_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_face_udp4_input_trace_t *t =
    va_arg (*args, hicn_face_udp4_input_trace_t *);

  s =
    format (s, "FACE_UDP4_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	    (int) t->pkt_type, t->sw_if_index, t->next_index,
	    (t->packet_data[0] & 0xf0) ==
	    0x40 ? format_ip4_header : format_ip6_header, t->packet_data,
	    sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_face_udp4_input_node) =
{
  .function = hicn_face_udp4_input_node_fn,
  .name = "hicn-face-udp4-input",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_face_udp4_input_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_face_udp4_input_error_strings),
  .error_strings = hicn_face_udp4_input_error_strings,
  .n_next_nodes = HICN_FACE_UDP4_INPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN_FACE_UDP4_INPUT_NEXT_DATA] = "hicn-data-pcslookup",
    [HICN_FACE_UDP4_INPUT_NEXT_MAPME] = "hicn-mapme-ack",
    [HICN_FACE_UDP4_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */


static uword
hicn_face_udp6_input_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
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
			       HICNFWD_ERROR_PROCESSED, stats.pkts_processed);

  vlib_node_increment_counter (vm, node->node_index,
			       HICNFWD_ERROR_DATAS, stats.pkts_data_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn_face_udp6_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_face_udp6_input_trace_t *t =
    va_arg (*args, hicn_face_udp6_input_trace_t *);

  s =
    format (s, "FACE_UDP6_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	    (int) t->pkt_type, t->sw_if_index, t->next_index,
	    (t->packet_data[0] & 0xf0) ==
	    0x40 ? format_ip4_header : format_ip6_header, t->packet_data,
	    sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_face_udp6_input_node) =
{
  .function = hicn_face_udp6_input_node_fn,
  .name = "hicn-face-udp6-input",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_face_udp6_input_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_face_udp6_input_error_strings),
  .error_strings = hicn_face_udp6_input_error_strings,
  .n_next_nodes = HICN_FACE_UDP6_INPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN_FACE_UDP6_INPUT_NEXT_DATA] = "hicn-data-pcslookup",
    [HICN_FACE_UDP6_INPUT_NEXT_MAPME] = "hicn-mapme-ack",
    [HICN_FACE_UDP6_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/******* Face Output *******/

always_inline void
hicn_face_udp4_encap (vlib_main_t * vm,
		      vlib_buffer_t * outer_b0,
		      hicn_face_t * face, u32 * next)
{
  ip4_header_t *ip0;
  udp_header_t *udp0;
  hicn_face_udp_t *face_udp = (hicn_face_udp_t *) face->data;

  /* ip */
  ip0 = vlib_buffer_get_current (outer_b0);
  clib_memcpy (ip0, &(face_udp->hdrs.ip4.ip), sizeof (ip4_header_t) +
	       sizeof (udp_header_t));

  /* Fix UDP length */
  udp0 = (udp_header_t *) (ip0 + 1);

  udp0->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, outer_b0) -
                                       sizeof (*ip0));

  ip0->length =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, outer_b0));

  outer_b0->flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
  outer_b0->flags |= VNET_BUFFER_F_OFFLOAD_IP_CKSUM;

  int is_iface = 0;
  ip_adjacency_t *adj;
  if (PREDICT_FALSE (face->shared.adj == ~0))
    is_iface = 1;
  else
    adj = adj_get (face->shared.adj);

  /* In case the adj is not complete, we look if a better one exists, otherwise we send an arp request
   * This is necessary to account for the case in which when we create a face, there isn't a /128(/32) adjacency and we match with a more general route which is in glean state
   * In this case in fact, the general route will not be update upone receiving of a arp or neighbour responde, but a new /128(/32) will be created
   */
  if (PREDICT_FALSE
      (is_iface || adj->lookup_next_index < IP_LOOKUP_NEXT_REWRITE))
    {
      fib_prefix_t fib_pfx;
      fib_node_index_t fib_entry_index;
      ip46_address_t ip46 =
	to_ip46 (0, (u8 *) & (face_udp->hdrs.ip4.ip.dst_address));
      fib_prefix_from_ip46_addr (&ip46, &fib_pfx);
      fib_pfx.fp_len = 32;

      u32 fib_index = fib_table_find_or_create_and_lock (fib_pfx.fp_proto,
							 HICN_FIB_TABLE,
							 FIB_SOURCE_PRIORITY_HI);

      fib_entry_index = fib_table_lookup (fib_index, &fib_pfx);

      face->shared.adj = fib_entry_get_adj (fib_entry_index);
      face->shared.flags &= ~HICN_FACE_FLAGS_IFACE;
      face->shared.flags |= HICN_FACE_FLAGS_FACE;

      adj = adj_get (face->shared.adj);
    }

  vnet_buffer (outer_b0)->ip.adj_index[VLIB_TX] = face->shared.adj;
  *next = adj->lookup_next_index;
}

always_inline void
hicn_face_udp6_encap (vlib_main_t * vm,
		      vlib_buffer_t * outer_b0,
		      hicn_face_t * face, u32 * next)
{
  int bogus0;
  u16 new_l0;
  ip6_header_t *ip0;
  udp_header_t *udp0;
  hicn_face_udp_t *face_udp = (hicn_face_udp_t *) face->data;

  /* ip */
  ip0 = vlib_buffer_get_current (outer_b0);
  clib_memcpy (ip0, &(face_udp->hdrs.ip6.ip), sizeof (ip6_header_t) +
	       sizeof (udp_header_t));
  new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, outer_b0)
				 - sizeof (*ip0));
  ip0->payload_length = new_l0;

  /* Fix UDP length */
  udp0 = (udp_header_t *) (ip0 + 1);
  udp0->length = new_l0;

  udp0->checksum =
    ip6_tcp_udp_icmp_compute_checksum (vm, outer_b0, ip0, &bogus0);

  ASSERT (bogus0 == 0);

  outer_b0->flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;

  int is_iface = 0;
  ip_adjacency_t *adj;
  if (PREDICT_FALSE (face->shared.adj == ~0))
    is_iface = 1;
  else
    adj = adj_get (face->shared.adj);

  /* In case the adj is not complete, we look if a better one exists, otherwise we send an arp request
   * This is necessary to account for the case in which when we create a face, there isn't a /128(/32) adjacency and we match with a more general route which is in glean state
   * In this case in fact, the general route will not be update upone receiving of a arp or neighbour responde, but a new /128(/32) will be created
   */
  if (PREDICT_FALSE (is_iface || adj->lookup_next_index < IP_LOOKUP_NEXT_REWRITE))
    {
      fib_prefix_t fib_pfx;
      fib_node_index_t fib_entry_index;
      ip46_address_t ip46 =
	to_ip46 (1, (u8 *) & (face_udp->hdrs.ip6.ip.dst_address));
      fib_prefix_from_ip46_addr (&ip46, &fib_pfx);
      fib_pfx.fp_len = 128;

      u32 fib_index = fib_table_find_or_create_and_lock (fib_pfx.fp_proto,
							 HICN_FIB_TABLE,
							 FIB_SOURCE_PRIORITY_HI);

      fib_entry_index = fib_table_lookup (fib_index, &fib_pfx);

      face->shared.adj = fib_entry_get_adj (fib_entry_index);
      face->shared.flags &= ~HICN_FACE_FLAGS_IFACE;
      face->shared.flags |= HICN_FACE_FLAGS_FACE;

      adj = adj_get (face->shared.adj);
    }

  vnet_buffer (outer_b0)->ip.adj_index[VLIB_TX] = face->shared.adj;

  *next = adj->lookup_next_index;
}

static char *hicn_face_udp4_output_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static char *hicn_face_udp6_output_error_strings[] = {
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
hicn_face_udp4_output_trace_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
}
hicn_face_udp6_output_trace_t;

#define HICN_FACE_UDP_ENCAP_IP4 hicn_face_udp4_encap
#define HICN_FACE_UDP_ENCAP_IP6 hicn_face_udp6_encap

#define TRACE_OUTPUT_PKT_UDP4 hicn_face_udp4_output_trace_t
#define TRACE_OUTPUT_PKT_UDP6 hicn_face_udp6_output_trace_t

#define IP_HEADER_4 ip4_header_t
#define IP_HEADER_6 ip6_header_t

#define face_output_x1(ipv)                                         \
  do {                                                              \
  vlib_buffer_t *b0;                                                \
  u32 bi0;                                                          \
  u32 next0 = IP_LOOKUP_NEXT_DROP;				    \
  hicn_face_t * face;                                               \
                                                                    \
  /* Prefetch for next iteration. */                                \
  if (n_left_from > 1)                                              \
    {                                                               \
      vlib_buffer_t *b1;                                            \
      b1 = vlib_get_buffer (vm, from[1]);                           \
      CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, STORE);             \
      CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES , LOAD);       \
    }                                                               \
  /* Dequeue a packet buffer */                                     \
  bi0 = from[0];                                                    \
  from += 1;                                                        \
  n_left_from -= 1;                                                 \
                                                                    \
  b0 = vlib_get_buffer (vm, bi0);                                       \
  hicn_face_id_t face_id = vnet_buffer (b0)->ip.adj_index[VLIB_TX];     \
  face =                                                                \
    hicn_dpoi_get_from_idx(face_id);                                    \
                                                                        \
  if (PREDICT_TRUE(face != NULL))                                       \
    {                                                                   \
      /* Adjust vlib buffer. Create space for the udp tunnel. */        \
      vlib_buffer_advance(b0, -(sizeof (IP_HEADER_##ipv) +		\
			       sizeof (udp_header_t)));			\
                                                                        \
                                                                        \
      HICN_FACE_UDP_ENCAP_IP##ipv                                       \
        (vm, b0, face, &next0);						\
      stats.pkts_interest_count += 1;					\
      vlib_increment_combined_counter (                                 \
                                   &counters[face_id * HICN_N_COUNTER], \
                                   thread_index,                        \
                                   HICN_FACE_COUNTERS_INTEREST_TX,      \
                                   1,                                   \
                                   vlib_buffer_length_in_chain(vm, b0));\
    }                                                                   \
                                                                        \
                                                                        \
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&            \
                     (b0->flags & VLIB_BUFFER_IS_TRACED)))              \
    {                                                                   \
      TRACE_OUTPUT_PKT_UDP##ipv *t =                                    \
        vlib_add_trace (vm, node, b0, sizeof (*t));                     \
      t->pkt_type = HICN_PKT_TYPE_INTEREST;                             \
      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];          \
      t->next_index = next0;                                            \
      clib_memcpy_fast (t->packet_data,					\
			vlib_buffer_get_current (b0) +                  \
                        SIZE_HICN_HEADER##ipv,                          \
			sizeof (t->packet_data));			\
    }                                                                   \
                                                                        \
  to_next[0] = bi0;                                                     \
  to_next += 1;                                                         \
  n_left_to_next -= 1;                                                  \
                                                                        \
                                                                        \
  /* Verify speculative enqueue, maybe switch current next frame */     \
  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,                \
                                   to_next, n_left_to_next,             \
                                   bi0, next0);                         \
  } while(0)                                                            \


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
      CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES , LOAD);       \
      CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES , LOAD);       \
    }                                                               \
                                                                    \
    /* Dequeue a packet buffer */                                   \
    bi0 = from[0];                                                  \
    bi1 = from[1];                                                  \
    from += 2;                                                      \
    n_left_from -= 2;                                               \
    to_next[0] = bi0;                                               \
    to_next[1] = bi1;                                               \
    to_next += 2;                                                   \
    n_left_to_next -= 2;                                            \
                                                                    \
    b0 = vlib_get_buffer (vm, bi0);                                     \
    b1 = vlib_get_buffer (vm, bi1);                                     \
                                                                        \
    hicn_face_id_t face_id0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];  \
    hicn_face_id_t face_id1 = vnet_buffer (b1)->ip.adj_index[VLIB_TX];  \
    face0 =                                                             \
      hicn_dpoi_get_from_idx(vnet_buffer (b0)->ip.adj_index[VLIB_TX]);  \
    face1 =                                                             \
      hicn_dpoi_get_from_idx(vnet_buffer (b1)->ip.adj_index[VLIB_TX]);  \
                                                                        \
    if (PREDICT_TRUE(face0 != NULL))                                    \
      {                                                                 \
        /* Adjust vlib buffer. Create space for the udp tunnel. */      \
        vlib_buffer_advance(b0, -(sizeof (IP_HEADER_##ipv) +		\
				  sizeof (udp_header_t)));		\
                                                                        \
                                                                        \
        HICN_FACE_UDP_ENCAP_IP##ipv                                     \
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
        /* Adjust vlib buffer. Create space for the udp tunnel. */      \
        vlib_buffer_advance(b1, -(sizeof (IP_HEADER_##ipv) +		\
				  sizeof (udp_header_t)));		\
                                                                        \
                                                                        \
        HICN_FACE_UDP_ENCAP_IP##ipv                                     \
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
                                                                        \
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&          \
                       (b0->flags & VLIB_BUFFER_IS_TRACED)))            \
      {                                                                 \
        TRACE_OUTPUT_PKT_UDP##ipv *t =                                  \
          vlib_add_trace (vm, node, b0, sizeof (*t));                   \
        t->pkt_type = HICN_PKT_TYPE_INTEREST;                           \
        t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];        \
        t->next_index = next0;                                          \
	clib_memcpy_fast (t->packet_data,				\
			  vlib_buffer_get_current (b0) +                \
                          SIZE_HICN_HEADER##ipv,			\
			  sizeof (t->packet_data));			\
      }                                                                 \
                                                                        \
                                                                        \
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&          \
                       (b1->flags & VLIB_BUFFER_IS_TRACED)))            \
      {                                                                 \
        TRACE_OUTPUT_PKT_UDP##ipv *t =                                  \
          vlib_add_trace (vm, node, b0, sizeof (*t));                   \
        t->pkt_type = HICN_PKT_TYPE_INTEREST;                           \
        t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];        \
        t->next_index = next1;                                          \
	clib_memcpy_fast (t->packet_data,				\
			  vlib_buffer_get_current (b1) +                \
                          SIZE_HICN_HEADER##ipv,			\
			  sizeof (t->packet_data));			\
      }                                                                 \
    /* Verify speculative enqueue, maybe switch current next frame */   \
    vlib_validate_buffer_enqueue_x2 (vm, node, next_index,              \
                                     to_next, n_left_to_next,           \
                                     bi0, bi1, next0, next1);           \
  } while(0)                                                            \


static uword
hicn_face_udp4_output_node_fn (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
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
hicn_face_udp4_output_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_face_udp4_output_trace_t *t =
    va_arg (*args, hicn_face_udp4_output_trace_t *);

  s =
    format (s, "FACE_UDP4_OUTPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	    (int) t->pkt_type, t->sw_if_index, t->next_index,
	    (t->packet_data[0] & 0xf0) ==
	    0x40 ? format_ip4_header : format_ip6_header, t->packet_data,
	    sizeof (t->packet_data));
  return (s);
}

/* *INDENT-OFF* */
/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_face_udp4_output_node) =
{
  .function = hicn_face_udp4_output_node_fn,
  .name = "hicn-face-udp4-output",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_face_udp4_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_face_udp4_output_error_strings),
  .error_strings = hicn_face_udp4_output_error_strings,
  .n_next_nodes = IP4_LOOKUP_N_NEXT,
  /* Reusing the list of nodes from lookup to be compatible with arp */
  .next_nodes = IP4_LOOKUP_NEXT_NODES,
};
/* *INDENT-ON* */

/* *INDENT-ON* */

static uword
hicn_face_udp6_output_node_fn (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
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
hicn_face_udp6_output_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_face_udp6_output_trace_t *t =
    va_arg (*args, hicn_face_udp6_output_trace_t *);

  s =
    format (s, "FACE_UDP6_OUTPUT: pkt: %d, sw_if_index %d, next index %d\n%u",
	    (int) t->pkt_type, t->sw_if_index, t->next_index,
	    (t->packet_data[0] & 0xf0) ==
	    0x40 ? format_ip4_header : format_ip6_header, t->packet_data,
	    sizeof (t->packet_data));
  return (s);
}

/* *INDENT-OFF* */
/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_face_udp6_output_node) =
{
  .function = hicn_face_udp6_output_node_fn,
  .name = "hicn-face-udp6-output",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_face_udp6_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_face_udp6_output_error_strings),
  .error_strings = hicn_face_udp6_output_error_strings,
  .n_next_nodes = IP6_LOOKUP_N_NEXT,
  /* Reusing the list of nodes from lookup to be compatible with neighbour discovery */
  .next_nodes = IP6_LOOKUP_NEXT_NODES,
};
/* *INDENT-ON* */

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
