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

#include "iface_udp_node.h"
#include "dpo_udp.h"
#include "../face.h"

#include "../../infra.h"
#include "../../hicn.h"

/**
 * @File
 *
 * Definition of the nodes for udp incomplete faces.
 */

vlib_node_registration_t hicn_iface_udp4_input_node;
vlib_node_registration_t hicn_iface_udp6_input_node;
vlib_node_registration_t hicn_iface_udp4_output_node;
vlib_node_registration_t hicn_iface_udp6_output_node;

u32 data_fwd_face_udp4_vlib_edge;
u32 data_fwd_face_udp6_vlib_edge;

void
hicn_iface_udp_init (vlib_main_t * vm)
{
  data_fwd_face_udp4_vlib_edge = vlib_node_add_next (vm,
						     hicn_data_fwd_node.index,
						     hicn_iface_udp4_output_node.index);

  data_fwd_face_udp6_vlib_edge = vlib_node_add_next (vm,
						     hicn_data_fwd_node.index,
						     hicn_iface_udp6_output_node.index);

  u32 temp_index4 = vlib_node_add_next (vm,
					hicn_interest_hitcs_node.index,
					hicn_iface_udp4_output_node.index);
  u32 temp_index6 = vlib_node_add_next (vm,
					hicn_interest_hitcs_node.index,
					hicn_iface_udp6_output_node.index);

  ASSERT (temp_index4 == data_fwd_face_udp4_vlib_edge);
  ASSERT (temp_index6 == data_fwd_face_udp6_vlib_edge);
}

static char *hicn_iface_udp4_input_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static char *hicn_iface_udp6_input_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

u32
get_face_udp4_output_node (void)
{
  return data_fwd_face_udp4_vlib_edge;
}

u32
get_face_udp6_output_node (void)
{
  return data_fwd_face_udp6_vlib_edge;
}

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
}
hicn_iface_udp4_input_trace_t;

typedef enum
{
  HICN_IFACE_UDP4_INPUT_NEXT_INTEREST,
  HICN_IFACE_UDP4_INPUT_NEXT_MAPME,
  HICN_IFACE_UDP4_INPUT_NEXT_ERROR_DROP,
  HICN_IFACE_UDP4_INPUT_N_NEXT,
} hicn_iface_udp4_input_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
}
hicn_iface_udp6_input_trace_t;

typedef enum
{
  HICN_IFACE_UDP6_INPUT_NEXT_INTEREST,
  HICN_IFACE_UDP6_INPUT_NEXT_MAPME,
  HICN_IFACE_UDP6_INPUT_NEXT_ERROR_DROP,
  HICN_IFACE_UDP6_INPUT_N_NEXT,
} hicn_iface_udp6_input_next_t;

#define ERROR_INPUT_UDP4 HICN_IFACE_UDP4_INPUT_NEXT_ERROR_DROP
#define ERROR_INPUT_UDP6 HICN_IFACE_UDP6_INPUT_NEXT_ERROR_DROP

#define IP_HEADER_4 ip4_header_t
#define IP_HEADER_6 ip6_header_t

#define NEXT_MAPME_UDP4 HICN_IFACE_UDP4_INPUT_NEXT_MAPME
#define NEXT_MAPME_UDP6 HICN_IFACE_UDP6_INPUT_NEXT_MAPME

#define NEXT_INTEREST_UDP4 HICN_IFACE_UDP4_INPUT_NEXT_INTEREST
#define NEXT_INTEREST_UDP6 HICN_IFACE_UDP6_INPUT_NEXT_INTEREST

#define HICN_IFACE_UDP_ADD_LOCK_IP4 hicn_dpo_udp4_add_and_lock
#define HICN_IFACE_UDP_ADD_LOCK_IP6 hicn_dpo_udp6_add_and_lock

#define GET_FACE_UDP4  get_face_udp4_output_node
#define GET_FACE_UDP6  get_face_udp6_output_node

#define TRACE_INPUT_PKT_UDP4 hicn_iface_udp4_input_trace_t
#define TRACE_INPUT_PKT_UDP6 hicn_iface_udp6_input_trace_t

#define iface_input_x1(ipv)						\
  do {									\
    vlib_buffer_t *b0;							\
    u32 bi0;								\
    u32 next0 = ERROR_INPUT_UDP##ipv;					\
    IP_HEADER_##ipv * ip_hdr = NULL;					\
    u8 * inner_ip_hdr = NULL;						\
    udp_header_t * udp_hdr = NULL;					\
    hicn_buffer_t * hicnb0;						\
    /* Prefetch for next iteration. */					\
    if (n_left_from > 1)						\
      {									\
	vlib_buffer_t *b1;						\
	b1 = vlib_get_buffer (vm, from[1]);				\
	CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, STORE);		\
	CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES , LOAD);		\
      }									\
    /* Dequeue a packet buffer */					\
    bi0 = from[0];							\
    from += 1;								\
    n_left_from -= 1;							\
    to_next[0] = bi0;							\
    to_next += 1;							\
    n_left_to_next -= 1;						\
									\
    b0 = vlib_get_buffer (vm, bi0);					\
    ip_hdr = (IP_HEADER_##ipv *) vlib_buffer_get_current(b0);		\
    udp_hdr = (udp_header_t *) (ip_hdr + 1);				\
    hicnb0 = hicn_get_buffer(b0);					\
									\
    stats.pkts_interest_count += 1;					\
									\
    inner_ip_hdr = (u8 *)(udp_hdr + 1);					\
    u8 is_v6 = hicn_is_v6((hicn_header_t *)inner_ip_hdr);               \
    u8 is_icmp = is_v6*(inner_ip_hdr[6] == IPPROTO_ICMPV6) +		\
      (1 - is_v6)*(inner_ip_hdr[9] == IPPROTO_ICMPV4);			\
									\
    next0 = is_icmp*NEXT_MAPME_UDP##ipv +				\
      (1-is_icmp)*NEXT_INTEREST_UDP##ipv;				\
									\
    HICN_IFACE_UDP_ADD_LOCK_IP##ipv					\
      (&(hicnb0->face_dpo_id),						\
       &(ip_hdr->dst_address),						\
       &(ip_hdr->src_address),						\
       udp_hdr->dst_port,						\
       udp_hdr->src_port,						\
       GET_FACE_UDP##ipv						\
       (),								\
       &hicnb0->flags,							\
       vnet_buffer(b0)->sw_if_index[VLIB_RX]);				\
									\
    vlib_buffer_advance(b0, sizeof(IP_HEADER_##ipv) +			\
			sizeof(udp_header_t));				\
									\
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&		\
		       (b0->flags & VLIB_BUFFER_IS_TRACED)))		\
      {									\
	TRACE_INPUT_PKT_UDP##ipv *t =					\
	  vlib_add_trace (vm, node, b0, sizeof (*t));			\
	t->pkt_type = HICN_PKT_TYPE_INTEREST;				\
	t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];	\
	t->next_index = next0;						\
	clib_memcpy_fast (t->packet_data,				\
			vlib_buffer_get_current (b0),			\
			sizeof (t->packet_data));			\
      }									\
                                                                        \
    vlib_increment_combined_counter (                                   \
                              &counters[hicnb0->face_dpo_id.dpoi_index  \
                                        * HICN_N_COUNTER], thread_index,\
                              HICN_FACE_COUNTERS_INTEREST_RX,           \
                              1,                                        \
                              vlib_buffer_length_in_chain(vm, b0));     \
									\
									\
    /* Verify speculative enqueue, maybe switch current next frame */	\
    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,		\
				     to_next, n_left_to_next,		\
				     bi0, next0);			\
  }while(0)


#define iface_input_x2(ipv)                                         \
  do {                                                              \
    vlib_buffer_t *b0, *b1;					    \
    u32 bi0, bi1;						    \
    u32 next0, next1 = ERROR_INPUT_UDP##ipv;			    \
    IP_HEADER_##ipv * ip_hdr0 = NULL, *ip_hdr1 = NULL;		    \
    u8 * inner_ip_hdr0 = NULL, *inner_ip_hdr1 = NULL;		    \
    udp_header_t * udp_hdr0 = NULL, *udp_hdr1 = NULL;		    \
    hicn_buffer_t * hicnb0, *hicnb1;				    \
								    \
    /* Prefetch for next iteration. */				    \
      {								    \
	vlib_buffer_t *b2, *b3;					    \
	b2 = vlib_get_buffer (vm, from[2]);			    \
	b3 = vlib_get_buffer (vm, from[3]);			    \
	CLIB_PREFETCH (b2, CLIB_CACHE_LINE_BYTES, STORE);	    \
	CLIB_PREFETCH (b3, CLIB_CACHE_LINE_BYTES, STORE);	    \
	CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES , LOAD);	    \
	CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES , LOAD);	    \
      }								    \
								    \
  /* Dequeue a packet buffer */                                     \
  bi0 = from[0];                                                    \
  bi1 = from[1];                                                    \
  from += 2;                                                        \
  n_left_from -= 2;                                                 \
  to_next[0] = bi0;                                                 \
  to_next[1] = bi1;                                                 \
  to_next += 2;                                                     \
  n_left_to_next -= 2;                                              \
                                                                    \
  b0 = vlib_get_buffer (vm, bi0);                                   \
  b1 = vlib_get_buffer (vm, bi1);                                   \
  ip_hdr0 = (IP_HEADER_##ipv *) vlib_buffer_get_current(b0);	    \
  ip_hdr1 = (IP_HEADER_##ipv *) vlib_buffer_get_current(b1);	    \
  udp_hdr0 = (udp_header_t *) (ip_hdr0 + 1);			    \
  udp_hdr1 = (udp_header_t *) (ip_hdr1 + 1);			    \
  hicnb0 = hicn_get_buffer(b0);                                     \
  hicnb1 = hicn_get_buffer(b1);                                     \
  								    \
  stats.pkts_interest_count += 2;					\
									\
  inner_ip_hdr0 = (u8 *)(udp_hdr0 + 1);					\
  inner_ip_hdr1 = (u8 *)(udp_hdr1 + 1);					\
  u8 is_v6_0 = hicn_is_v6((hicn_header_t *)inner_ip_hdr0);              \
  u8 is_v6_1 = hicn_is_v6((hicn_header_t *)inner_ip_hdr1);              \
  u8 is_icmp0 = is_v6_0*(inner_ip_hdr0[6] == IPPROTO_ICMPV6) +		\
    (1 - is_v6_0)*(inner_ip_hdr0[9] == IPPROTO_ICMPV4);		\
  u8 is_icmp1 = is_v6_1*(inner_ip_hdr1[6] == IPPROTO_ICMPV6) +		\
    (1 - is_v6_1)*(inner_ip_hdr1[9] == IPPROTO_ICMPV4);		\
  									\
  next0 = is_icmp0*NEXT_MAPME_UDP##ipv +				\
    (1-is_icmp0)*NEXT_INTEREST_UDP##ipv;				\
  next1 = is_icmp1*NEXT_MAPME_UDP##ipv +				\
    (1-is_icmp1)*NEXT_INTEREST_UDP##ipv;				\
  									\
  HICN_IFACE_UDP_ADD_LOCK_IP##ipv					\
    (&(hicnb0->face_dpo_id),						\
     &(ip_hdr0->dst_address),						\
     &(ip_hdr0->src_address),						\
     udp_hdr0->dst_port,						\
     udp_hdr0->src_port,						\
     GET_FACE_UDP##ipv							\
     (),								\
     &hicnb0->flags,							\
     vnet_buffer(b0)->sw_if_index[VLIB_RX]);				\
									\
									\
    HICN_IFACE_UDP_ADD_LOCK_IP##ipv					\
    (&(hicnb1->face_dpo_id),						\
     &(ip_hdr1->dst_address),						\
     &(ip_hdr1->src_address),						\
     udp_hdr1->dst_port,						\
     udp_hdr1->src_port,						\
     GET_FACE_UDP##ipv							\
     (),								\
     &hicnb1->flags,							\
     vnet_buffer(b1)->sw_if_index[VLIB_RX]);				\
									\
    vlib_buffer_advance(b0, sizeof(IP_HEADER_##ipv) +			\
			sizeof(udp_header_t));				\
									\
    vlib_buffer_advance(b1, sizeof(IP_HEADER_##ipv) +			\
			sizeof(udp_header_t));				\
    									\
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&		\
		       (b0->flags & VLIB_BUFFER_IS_TRACED)))		\
      {									\
	TRACE_INPUT_PKT_UDP##ipv *t =					\
	  vlib_add_trace (vm, node, b0, sizeof (*t));			\
	t->pkt_type = HICN_PKT_TYPE_INTEREST;				\
	t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];	\
	t->next_index = next0;						\
	clib_memcpy_fast (t->packet_data,				\
			  vlib_buffer_get_current (b0),			\
			  sizeof (t->packet_data));			\
      }									\
    									\
									\
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&		\
		       (b1->flags & VLIB_BUFFER_IS_TRACED)))		\
      {									\
	TRACE_INPUT_PKT_UDP##ipv *t =					\
	  vlib_add_trace (vm, node, b1, sizeof (*t));			\
	t->pkt_type = HICN_PKT_TYPE_INTEREST;				\
	t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];	\
	t->next_index = next1;						\
	clib_memcpy_fast (t->packet_data,				\
			  vlib_buffer_get_current (b1),			\
			  sizeof (t->packet_data));			\
      }									\
									\
    vlib_increment_combined_counter (                                   \
                              &counters[hicnb0->face_dpo_id.dpoi_index  \
                                        * HICN_N_COUNTER], thread_index,\
                              HICN_FACE_COUNTERS_INTEREST_RX,           \
                              1,                                        \
                              vlib_buffer_length_in_chain(vm, b0));     \
                                                                        \
    vlib_increment_combined_counter (                                   \
                              &counters[hicnb1->face_dpo_id.dpoi_index  \
                                        * HICN_N_COUNTER], thread_index,\
                              HICN_FACE_COUNTERS_INTEREST_RX,           \
                              1,                                        \
                              vlib_buffer_length_in_chain(vm, b1));     \
    									\
    /* Verify speculative enqueue, maybe switch current next frame */	\
    vlib_validate_buffer_enqueue_x2 (vm, node, next_index,		\
				     to_next, n_left_to_next,		\
				     bi0, bi1, next0, next1);		\
  }while(0)


static uword
hicn_iface_udp4_input_node_fn (vlib_main_t * vm,
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
	  iface_input_x2 (4);
	}

      /* Dual loop, X1 */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  iface_input_x1 (4);
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
hicn_iface_udp4_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_iface_udp4_input_trace_t *t =
    va_arg (*args, hicn_iface_udp4_input_trace_t *);

  s =
    format (s, "IFACE_UDP4_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
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
VLIB_REGISTER_NODE (hicn_iface_udp4_input_node) =

{
  .function = hicn_iface_udp4_input_node_fn,
  .name = "hicn-iface-udp4-input",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_iface_udp4_input_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_iface_udp4_input_error_strings),
  .error_strings = hicn_iface_udp4_input_error_strings,
  .n_next_nodes = HICN_IFACE_UDP4_INPUT_N_NEXT,
  .next_nodes =
  {
    [HICN_IFACE_UDP4_INPUT_NEXT_INTEREST] = "hicn-interest-pcslookup",
    [HICN_IFACE_UDP4_INPUT_NEXT_MAPME] = "hicn-mapme-ctrl",
    [HICN_IFACE_UDP4_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */


static uword
hicn_iface_udp6_input_node_fn (vlib_main_t * vm,
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
	  iface_input_x2 (6);
	}

      /* Dual loop, X1 */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  iface_input_x1 (6);
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
hicn_iface_udp6_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_iface_udp6_input_trace_t *t =
    va_arg (*args, hicn_iface_udp6_input_trace_t *);

  s =
    format (s, "IFACE_UDP6_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
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
VLIB_REGISTER_NODE (hicn_iface_udp6_input_node) =
{
  .function = hicn_iface_udp6_input_node_fn,
  .name = "hicn-iface-udp6-input",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_iface_udp6_input_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_iface_udp6_input_error_strings),
  .error_strings = hicn_iface_udp6_input_error_strings,
  .n_next_nodes = HICN_IFACE_UDP6_INPUT_N_NEXT,
  .next_nodes =
  {
    [HICN_IFACE_UDP6_INPUT_NEXT_INTEREST] = "hicn-interest-pcslookup",
    [HICN_IFACE_UDP6_INPUT_NEXT_MAPME] = "hicn-mapme-ctrl",
    [HICN_IFACE_UDP6_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/******* Iface Output *******/

always_inline void
hicn_iface_udp4_encap (vlib_main_t * vm,
		       vlib_buffer_t * b0, hicn_face_t * face)
{
  u16 new_l0 = 0;
  ip4_header_t *ip0;
  udp_header_t *udp0;
  hicn_face_udp_t *face_udp = (hicn_face_udp_t *) face->data;

  /* Adjust vlib buffers */
  /* Set the right length on the header buffer */
  /* Move the next buffer current data pointer back to the ip+tcp header (hicn header) */
  word offset = sizeof (ip4_header_t) + sizeof (udp_header_t);
  vlib_buffer_advance (b0, -offset);

  /* ip */
  ip0 = vlib_buffer_get_current (b0);
  clib_memcpy (ip0, &(face_udp->hdrs.ip4.ip), sizeof (ip4_header_t) +
	       sizeof (udp_header_t));

  /* Fix UDP length */
  udp0 = (udp_header_t *) (ip0 + 1);

  new_l0 =
    clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0) -
			  sizeof (*ip0));
  udp0->length = new_l0;

  outer_b0->flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
  outer_b0->flags |= VNET_BUFFER_F_OFFLOAD_IP_CKSUM;

  ip0->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
}

always_inline void
hicn_iface_udp6_encap (vlib_main_t * vm,
		       vlib_buffer_t * b0, hicn_face_t * face)
{
  int bogus0;
  u16 new_l0;
  ip6_header_t *ip0;
  udp_header_t *udp0;
  hicn_face_udp_t *face_udp = (hicn_face_udp_t *) face->data;

  /* Adjust vlib buffer */
  word offset = sizeof (ip6_header_t) + sizeof (udp_header_t);
  vlib_buffer_advance (b0, -offset);

  /* ip */
  ip0 = vlib_buffer_get_current (b0);
  clib_memcpy (ip0, &(face_udp->hdrs.ip6.ip), sizeof (ip6_header_t) +
	       sizeof (udp_header_t));

  new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
				 - sizeof (*ip0));

  ip0->payload_length = new_l0;

  /* Fix UDP length */
  udp0 = (udp_header_t *) (ip0 + 1);
  udp0->length = new_l0;

  outer_b0->flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
}

static char *hicn_iface_udp4_output_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static char *hicn_iface_udp6_output_error_strings[] = {
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
hicn_iface_udp4_output_trace_t;

typedef enum
{
  HICN_IFACE_UDP4_OUTPUT_NEXT_LOOKUP,
  HICN_IFACE_UDP4_OUTPUT_NEXT_ERROR_DROP,
  HICN_IFACE_UDP4_OUTPUT_N_NEXT,
} hicn_iface_udp4_output_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[60];
}
hicn_iface_udp6_output_trace_t;

typedef enum
{
  HICN_IFACE_UDP6_OUTPUT_NEXT_LOOKUP,
  HICN_IFACE_UDP6_OUTPUT_NEXT_ERROR_DROP,
  HICN_IFACE_UDP6_OUTPUT_N_NEXT,
} hicn_iface_udp6_output_next_t;

#define ERROR_OUTPUT_UDP4 HICN_IFACE_UDP4_OUTPUT_NEXT_ERROR_DROP
#define ERROR_OUTPUT_UDP6 HICN_IFACE_UDP6_OUTPUT_NEXT_ERROR_DROP

#define IP_HEADER_4 ip4_header_t
#define IP_HEADER_6 ip6_header_t

#define NEXT_LOOKUP_UDP4 HICN_IFACE_UDP4_OUTPUT_NEXT_LOOKUP
#define NEXT_LOOKUP_UDP6 HICN_IFACE_UDP6_OUTPUT_NEXT_LOOKUP

#define HICN_IFACE_UDP_ADD_LOCK_IP4 hicn_dpo_udp4_add_and_lock
#define HICN_IFACE_UDP_ADD_LOCK_IP6 hicn_dpo_udp6_add_and_lock

#define HICN_FACE_UDP_ENCAP_IP4 hicn_iface_udp4_encap
#define HICN_FACE_UDP_ENCAP_IP6 hicn_iface_udp6_encap

#define TRACE_OUTPUT_PKT_UDP4 hicn_iface_udp4_output_trace_t
#define TRACE_OUTPUT_PKT_UDP6 hicn_iface_udp6_output_trace_t

#define SIZE_HICN_HEADER4 sizeof(ip4_header_t) + sizeof(udp_header_t)
#define SIZE_HICN_HEADER6 sizeof(ip6_header_t) + sizeof(udp_header_t)

#define iface_output_x1(ipv)                                        \
  do {                                                              \
  vlib_buffer_t *b0;                                                \
  u32 bi0;                                                          \
  u32 next0 = ERROR_OUTPUT_UDP##ipv;                                \
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
  to_next[0] = bi0;                                                 \
  to_next += 1;                                                     \
  n_left_to_next -= 1;                                              \
  								    \
  b0 = vlib_get_buffer (vm, bi0);                                       \
									\
  hicn_face_id_t face_id = vnet_buffer (b0)->ip.adj_index[VLIB_TX];     \
  face =                                                                \
    hicn_dpoi_get_from_idx(face_id);                                    \
                                                                        \
  if (PREDICT_TRUE(face != NULL))                                       \
    {                                                                   \
      HICN_FACE_UDP_ENCAP_IP##ipv					\
        (vm, b0, face);                                                 \
      next0 = NEXT_LOOKUP_UDP##ipv;                                     \
      stats.pkts_data_count += 1;					\
      vlib_increment_combined_counter (                                 \
                                  &counters[face_id * HICN_N_COUNTER],  \
                                  thread_index,                         \
                                  HICN_FACE_COUNTERS_DATA_TX,           \
                                  1,                                    \
                                  vlib_buffer_length_in_chain(vm, b0)); \
    }                                                                   \
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
                                                                        \
  /* Verify speculative enqueue, maybe switch current next frame */     \
  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,                \
                                   to_next, n_left_to_next,             \
                                   bi0, next0);                         \
  } while(0)

#define iface_output_x2(ipv)						\
  do {									\
    vlib_buffer_t *b0, *b1;						\
    u32 bi0, bi1;							\
    u32 next0 = ERROR_OUTPUT_UDP##ipv, next1 = ERROR_OUTPUT_UDP##ipv;	\
    hicn_face_t *face0, *face1;						\
									\
    /* Prefetch for next iteration. */					\
    {									\
      vlib_buffer_t *b2, *b3;						\
      b2 = vlib_get_buffer (vm, from[2]);				\
      b3 = vlib_get_buffer (vm, from[3]);				\
      CLIB_PREFETCH (b2, CLIB_CACHE_LINE_BYTES, STORE);			\
      CLIB_PREFETCH (b3, CLIB_CACHE_LINE_BYTES, STORE);			\
      CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES , LOAD);		\
      CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES , LOAD);		\
    }									\
									\
    /* Dequeue packets buffers */					\
    bi0 = from[0];							\
    bi1 = from[1];							\
    from += 2;								\
    n_left_from -= 2;							\
    to_next[0] = bi0;							\
    to_next[1] = bi1;							\
    to_next += 2;							\
    n_left_to_next -= 2;						\
    									\
    b0 = vlib_get_buffer (vm, bi0);					\
    b1 = vlib_get_buffer (vm, bi1);					\
									\
    hicn_face_id_t face_id0 = vnet_buffer (b0)->ip.adj_index[VLIB_TX];  \
    hicn_face_id_t face_id1 = vnet_buffer (b1)->ip.adj_index[VLIB_TX];  \
    face0 =								\
      hicn_dpoi_get_from_idx(face_id0);                                 \
    face1 =								\
      hicn_dpoi_get_from_idx(face_id1);                                 \
                                                                        \
    if (PREDICT_TRUE(face0 != NULL))					\
      {									\
	HICN_FACE_UDP_ENCAP_IP##ipv					\
	  (vm, b0, face0);						\
	next0 = NEXT_LOOKUP_UDP##ipv;					\
	stats.pkts_data_count += 1;					\
        vlib_increment_combined_counter (                               \
                                  &counters[face_id0 * HICN_N_COUNTER], \
                                  thread_index,                         \
                                  HICN_FACE_COUNTERS_DATA_TX,           \
                                  1,                                    \
                                  vlib_buffer_length_in_chain(vm, b0)); \
      }									\
									\
    if (PREDICT_TRUE(face1 != NULL))					\
      {									\
	HICN_FACE_UDP_ENCAP_IP##ipv					\
	  (vm, b1, face1);						\
	next1 = NEXT_LOOKUP_UDP##ipv;					\
	stats.pkts_data_count += 1;					\
        vlib_increment_combined_counter (                               \
                                  &counters[face_id1 * HICN_N_COUNTER], \
                                  thread_index,                         \
                                  HICN_FACE_COUNTERS_DATA_TX,           \
                                  1,                                    \
                                  vlib_buffer_length_in_chain(vm, b1)); \
      }									\
									\
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&		\
		       (b0->flags & VLIB_BUFFER_IS_TRACED)))		\
      {									\
	TRACE_OUTPUT_PKT_UDP##ipv *t =					\
	  vlib_add_trace (vm, node, b0, sizeof (*t));			\
	t->pkt_type = HICN_PKT_TYPE_INTEREST;				\
	t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];	\
	t->next_index = next0;						\
	clib_memcpy_fast (t->packet_data,				\
			  vlib_buffer_get_current (b0) +                \
                          SIZE_HICN_HEADER##ipv,			\
			  sizeof (t->packet_data));			\
      }									\
                                                                        \
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&		\
		       (b1->flags & VLIB_BUFFER_IS_TRACED)))		\
      {									\
	TRACE_OUTPUT_PKT_UDP##ipv *t =					\
	  vlib_add_trace (vm, node, b1, sizeof (*t));			\
	t->pkt_type = HICN_PKT_TYPE_INTEREST;				\
	t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];	\
	t->next_index = next1;						\
	clib_memcpy_fast (t->packet_data,				\
			  vlib_buffer_get_current (b1) +                \
                          SIZE_HICN_HEADER##ipv,			\
			  sizeof (t->packet_data));			\
      }									\
									\
									\
  /* Verify speculative enqueue, maybe switch current next frame */     \
  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,                \
                                   to_next, n_left_to_next,             \
                                   bi0, bi1, next0, next1);		\
  } while(0)


static uword
hicn_iface_udp4_output_node_fn (vlib_main_t * vm,
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

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  iface_output_x2 (4);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  iface_output_x1 (4);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       HICNFWD_ERROR_DATAS, stats.pkts_data_count);

  return (frame->n_vectors);
}

/* packet trace format function */
static u8 *
hicn_iface_udp4_output_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_iface_udp4_output_trace_t *t =
    va_arg (*args, hicn_iface_udp4_output_trace_t *);

  s =
    format (s,
	    "IFACE_UDP4_OUTPUT: pkt: %d, out face %d, next index %d\n%U",
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
VLIB_REGISTER_NODE (hicn_iface_udp4_output_node) =
{
  .function = hicn_iface_udp4_output_node_fn,
  .name = "hicn-iface-udp4-output",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_iface_udp4_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_iface_udp4_output_error_strings),
  .error_strings = hicn_iface_udp4_output_error_strings,
  .n_next_nodes = HICN_IFACE_UDP4_OUTPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN_IFACE_UDP4_OUTPUT_NEXT_LOOKUP] = "ip4-lookup",
    [HICN_IFACE_UDP4_OUTPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */


static uword
hicn_iface_udp6_output_node_fn (vlib_main_t * vm,
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

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  iface_output_x2 (6);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  iface_output_x1 (6);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
			       HICNFWD_ERROR_DATAS, stats.pkts_data_count);

  return (frame->n_vectors);

}

/* packet trace format function */
static u8 *
hicn_iface_udp6_output_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_iface_udp6_output_trace_t *t =
    va_arg (*args, hicn_iface_udp6_output_trace_t *);

  s =
    format (s,
	    "IFACE_UDP6_OUTPUT: pkt: %d, out face %d, next index %d\n%U",
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
VLIB_REGISTER_NODE (hicn_iface_udp6_output_node) =
{
  .function = hicn_iface_udp6_output_node_fn,
  .name = "hicn-iface-udp6-output",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_iface_udp6_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_iface_udp6_output_error_strings),
  .error_strings = hicn_iface_udp6_output_error_strings,
  .n_next_nodes = HICN_IFACE_UDP6_OUTPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN_IFACE_UDP6_OUTPUT_NEXT_LOOKUP] = "ip6-lookup",
    [HICN_IFACE_UDP6_OUTPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
