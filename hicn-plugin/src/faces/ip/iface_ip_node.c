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

#include <hicn/hicn.h>
#include "face_ip.h"
#include "dpo_ip.h"
#include "../../strategy_dpo_manager.h"
#include "../face.h"
#include "../../infra.h"
#include "../../cache_policies/cs_lru.h"

/**
 * @File
 *
 * Definition of the nodes for ip incomplete faces.
 */

vlib_node_registration_t hicn_iface_ip4_input_node;
vlib_node_registration_t hicn_iface_ip4_output_node;
vlib_node_registration_t hicn_iface_ip6_input_node;
vlib_node_registration_t hicn_iface_ip6_output_node;

u32 data_fwd_iface_ip4_vlib_edge;
u32 data_fwd_iface_ip6_vlib_edge;

void
hicn_iface_ip_init (vlib_main_t * vm)
{
  u32 temp_index4 = vlib_node_add_next (vm,
					hicn_interest_hitcs_node.index,
					hicn_iface_ip4_output_node.index);
  u32 temp_index6 = vlib_node_add_next (vm,
					hicn_interest_hitcs_node.index,
					hicn_iface_ip6_output_node.index);

  data_fwd_iface_ip4_vlib_edge = vlib_node_add_next (vm,
						     hicn_data_fwd_node.index,
						     hicn_iface_ip4_output_node.
						     index);

  data_fwd_iface_ip6_vlib_edge = vlib_node_add_next (vm,
						     hicn_data_fwd_node.index,
						     hicn_iface_ip6_output_node.
						     index);

  ASSERT (temp_index4 == data_fwd_iface_ip4_vlib_edge);
  ASSERT (temp_index6 == data_fwd_iface_ip6_vlib_edge);
}

static char *hicn_iface_ip4_input_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static char *hicn_iface_ip6_input_error_strings[] = {
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
  u8 packet_data[128 - 1 * sizeof (u32)];
} hicn_iface_ip4_input_trace_t;

typedef enum
{
  HICN_IFACE_IP4_INPUT_NEXT_INTEREST,
  HICN_IFACE_IP4_INPUT_NEXT_MAPME,
  HICN_IFACE_IP4_INPUT_NEXT_ERROR_DROP,
  HICN_IFACE_IP4_INPUT_N_NEXT,
} hicn_iface_ip4_input_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[128 - 1 * sizeof (u32)];
} hicn_iface_ip6_input_trace_t;

typedef enum
{
  HICN_IFACE_IP6_INPUT_NEXT_INTEREST,
  HICN_IFACE_IP6_INPUT_NEXT_MAPME,
  HICN_IFACE_IP6_INPUT_NEXT_ERROR_DROP,
  HICN_IFACE_IP6_INPUT_N_NEXT,
} hicn_iface_ip6_input_next_t;

#define NEXT_MAPME_IP4 HICN_IFACE_IP4_INPUT_NEXT_MAPME
#define NEXT_MAPME_IP6 HICN_IFACE_IP6_INPUT_NEXT_MAPME

#define NEXT_INTEREST_IP4 HICN_IFACE_IP6_INPUT_NEXT_INTEREST
#define NEXT_INTEREST_IP6 HICN_IFACE_IP6_INPUT_NEXT_INTEREST

#define ADDRESS_IP4 ip_interface_address_t *ia = 0;ip4_address_t *local_address = ip4_interface_first_address(&ip4_main, swif, &ia)
#define ADDRESS_IP6 ip6_address_t *local_address = ip6_interface_first_address(&ip6_main, swif)

#define ADDRESSX2_IP4 ip_interface_address_t *ia0, *ia1; ia0 = ia1 = 0;                \
  ip4_address_t *local_address0 = ip4_interface_first_address(&ip4_main, swif0, &ia0); \
  ip4_address_t *local_address1 = ip4_interface_first_address(&ip4_main, swif1, &ia1);

#define ADDRESSX2_IP6 ip6_address_t *local_address0 = ip6_interface_first_address(&ip6_main, swif0); \
  ip6_address_t *local_address1 = ip6_interface_first_address(&ip6_main, swif1);

#define DPO_ADD_LOCK_IP4 hicn_dpo_ip4_add_and_lock_from_remote
#define DPO_ADD_LOCK_IP6 hicn_dpo_ip6_add_and_lock_from_remote

#define VLIB_EDGE_IP4 data_fwd_iface_ip4_vlib_edge
#define VLIB_EDGE_IP6 data_fwd_iface_ip6_vlib_edge

#define IP_HEADER_4 ip4_header_t
#define IP_HEADER_6 ip6_header_t

#define TRACE_INPUT_PKT_IP4 hicn_iface_ip4_input_trace_t
#define TRACE_INPUT_PKT_IP6 hicn_iface_ip6_input_trace_t

#define iface_input_x1(ipv)                                             \
  do {                                                                  \
  vlib_buffer_t *b0;                                                    \
  u32 bi0, next0;                                                       \
  IP_HEADER_##ipv * ip_hdr = NULL;                                      \
  hicn_buffer_t * hicnb0;                                               \
  u32 swif;                                                             \
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
  stats.pkts_interest_count += 1;                                       \
                                                                        \
  u8 is_icmp = ip_hdr->protocol == IPPROTO_ICMPV##ipv;                  \
                                                                        \
  next0 = is_icmp*NEXT_MAPME_IP##ipv +                                  \
    (1-is_icmp)*NEXT_INTEREST_IP##ipv;                                  \
                                                                        \
  swif = vnet_buffer (b0)->sw_if_index[VLIB_RX];                        \
                                                                        \
  ADDRESS_IP##ipv;                                                      \
                                                                        \
  DPO_ADD_LOCK_IP##ipv                                                  \
  (&(hicnb0->face_dpo_id),                                              \
   &hicnb0->flags,                                                      \
   local_address,                                                       \
   &(ip_hdr->src_address),                                              \
   vnet_buffer(b0)->sw_if_index[VLIB_RX],                               \
   VLIB_EDGE_IP##ipv);                                                  \
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
									\
    }                                                                   \
                                                                        \
                                                                        \
  /* Verify speculative enqueue, maybe switch current next frame */     \
  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,                \
                                   to_next, n_left_to_next,             \
                                   bi0, next0);                         \
  }while(0)


#define iface_input_x2(ipv)                                             \
  do {                                                                  \
    vlib_buffer_t *b0, *b1;                                             \
    u32 bi0, bi1, next0, next1;                                         \
    IP_HEADER_##ipv * ip_hdr0 = NULL;                                   \
    IP_HEADER_##ipv * ip_hdr1 = NULL;                                   \
    hicn_buffer_t *hicnb0, *hicnb1;                                     \
    u32 swif0, swif1;                                                   \
                                                                        \
    /* Prefetch for next iteration. */                                  \
    vlib_buffer_t *b2, *b3;                                             \
    b2 = vlib_get_buffer (vm, from[2]);                                 \
    b3 = vlib_get_buffer (vm, from[3]);                                 \
    CLIB_PREFETCH (b2, 2*CLIB_CACHE_LINE_BYTES, STORE);			\
    CLIB_PREFETCH (b3, 2*CLIB_CACHE_LINE_BYTES, STORE);			\
    CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES , LOAD);             \
    CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES , LOAD);             \
                                                                        \
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
    stats.pkts_interest_count += 2;                                     \
                                                                        \
    u8 is_icmp0 = ip_hdr0->protocol == IPPROTO_ICMPV##ipv;              \
    u8 is_icmp1 = ip_hdr1->protocol == IPPROTO_ICMPV##ipv;              \
                                                                        \
    next0 = is_icmp0*NEXT_MAPME_IP##ipv +                               \
      (1-is_icmp0)*NEXT_INTEREST_IP##ipv;                               \
                                                                        \
    next1 = is_icmp1*NEXT_MAPME_IP##ipv +                               \
      (1-is_icmp1)*NEXT_INTEREST_IP##ipv;                               \
                                                                        \
    swif0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];                     \
    swif1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];                     \
                                                                        \
    ADDRESSX2_IP##ipv;                                                  \
                                                                        \
    DPO_ADD_LOCK_IP##ipv                                                \
      (&(hicnb0->face_dpo_id),                                          \
       &hicnb0->flags,                                                  \
       local_address0,                                                  \
       &(ip_hdr0->src_address),                                         \
       vnet_buffer(b0)->sw_if_index[VLIB_RX],                           \
       VLIB_EDGE_IP##ipv);                                              \
                                                                        \
    DPO_ADD_LOCK_IP##ipv                                                \
      (&(hicnb1->face_dpo_id),                                          \
       &hicnb1->flags,                                                  \
       local_address1,                                                  \
       &(ip_hdr1->src_address),                                         \
       vnet_buffer(b1)->sw_if_index[VLIB_RX],                           \
       VLIB_EDGE_IP##ipv);                                              \
                                                                        \
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&          \
                       (b0->flags & VLIB_BUFFER_IS_TRACED)))            \
      {                                                                 \
        TRACE_INPUT_PKT_IP##ipv *t =                                    \
          vlib_add_trace (vm, node, b0, sizeof (*t));                   \
        t->pkt_type = HICN_PKT_TYPE_INTEREST;                           \
        t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];        \
        t->next_index = next0;                                          \
	clib_memcpy_fast (t->packet_data,				\
			  vlib_buffer_get_current (b0),			\
			  sizeof (t->packet_data));			\
      }                                                                 \
                                                                        \
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&          \
                       (b1->flags & VLIB_BUFFER_IS_TRACED)))            \
      {                                                                 \
        TRACE_INPUT_PKT_IP##ipv *t =                                    \
          vlib_add_trace (vm, node, b1, sizeof (*t));                   \
        t->pkt_type = HICN_PKT_TYPE_INTEREST;                           \
        t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];        \
        t->next_index = next1;                                          \
	clib_memcpy_fast (t->packet_data,				\
			  vlib_buffer_get_current (b1),			\
			  sizeof (t->packet_data));			\
      }                                                                 \
                                                                        \
    /* Verify speculative enqueue, maybe switch current next frame */   \
    vlib_validate_buffer_enqueue_x2 (vm, node, next_index,              \
                                     to_next, n_left_to_next,           \
                                     bi0, bi1, next0, next1);           \
  }while(0)

static uword
hicn_iface_ip4_input_node_fn (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };

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
hicn_iface_ip4_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_iface_ip4_input_trace_t *t =
    va_arg (*args, hicn_iface_ip4_input_trace_t *);

  s = format (s, "IFACE_IP4_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	      (int) t->pkt_type, t->sw_if_index, t->next_index, format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_iface_ip4_input_node) =
{
  .function = hicn_iface_ip4_input_node_fn,
  .name = "hicn-iface-ip4-input",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_iface_ip4_input_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_iface_ip4_input_error_strings),
  .error_strings = hicn_iface_ip4_input_error_strings,
  .n_next_nodes = HICN_IFACE_IP4_INPUT_N_NEXT,
  /* edit / add dispositions*/
  .next_nodes =
  {
    [HICN_IFACE_IP4_INPUT_NEXT_INTEREST] = "hicn-interest-pcslookup",
    [HICN_IFACE_IP4_INPUT_NEXT_MAPME] = "hicn-mapme-ctrl",
    [HICN_IFACE_IP4_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

static uword
hicn_iface_ip6_input_node_fn (vlib_main_t * vm,
			      vlib_node_runtime_t * node,
			      vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };

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
hicn_iface_ip6_input_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_iface_ip6_input_trace_t *t =
    va_arg (*args, hicn_iface_ip6_input_trace_t *);

  s = format (s, "IFACE_IP6_INPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
	      (int) t->pkt_type, t->sw_if_index, t->next_index, format_ip6_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_iface_ip6_input_node) =
{
  .function = hicn_iface_ip6_input_node_fn,
  .name = "hicn-iface-ip6-input",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_iface_ip6_input_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_iface_ip6_input_error_strings),
  .error_strings = hicn_iface_ip6_input_error_strings,
  .n_next_nodes = HICN_IFACE_IP6_INPUT_N_NEXT,
  /* edit / add dispositions*/
  .next_nodes =
  {
    [HICN_IFACE_IP6_INPUT_NEXT_INTEREST] = "hicn-interest-pcslookup",
    [HICN_IFACE_IP6_INPUT_NEXT_MAPME] = "hicn-mapme-ctrl",
    [HICN_IFACE_IP6_INPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */


/**** IFACE OUTPUT *****/

static inline void
hicn_rewrite_iface_data4 (vlib_main_t * vm, vlib_buffer_t * b0,
			  const hicn_face_t * iface)
{
  ip4_header_t *ip0;

  /* Get the pointer to the old ip and tcp header */
  ip0 = vlib_buffer_get_current (b0);

  /* Set up the ip6 header */
  /* IP4 lenght contains the size of the ip4 header too */
  u16 sval = (vlib_buffer_length_in_chain (vm, b0));
  ip0->length = clib_host_to_net_u16 (sval);
  ip0->ttl = 254;		// FIXME TTL

  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ~0;
  hicn_header_t *hicn = vlib_buffer_get_current (b0);

  ip46_address_t temp_addr;
  ip46_address_reset (&temp_addr);
  hicn_face_ip_t *iface_ip = (hicn_face_ip_t *) iface->data;
  hicn_type_t type = hicn_get_buffer (b0)->type;
  hicn_ops_vft[type.l1]->rewrite_data (type, &hicn->protocol,
				       &(iface_ip->remote_addr), &(temp_addr),
				       iface->shared.pl_id);
}

static inline void
hicn_rewrite_iface_data6 (vlib_main_t * vm, vlib_buffer_t * b0,
			  const hicn_face_t * iface)
{
  ip6_header_t *ip0;

  /* Get the pointer to the old ip and tcp header */
  /* Copy the previous ip and tcp header to the new portion of memory */
  ip0 = vlib_buffer_get_current (b0);

  /* Set up the ip6 header */
  /* IP6 lenght does not include the size of the ip6 header */
  u16 sval = (vlib_buffer_length_in_chain (vm, b0) - (sizeof (ip6_header_t)));
  ip0->payload_length = clib_host_to_net_u16 (sval);
  ip0->hop_limit = HICN_IP6_HOP_LIMIT;

  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ~0;
  hicn_header_t *hicn = vlib_buffer_get_current (b0);

  ip46_address_t temp_addr;
  ip46_address_reset (&temp_addr);
  hicn_face_ip_t *iface_ip = (hicn_face_ip_t *) iface->data;
  hicn_type_t type = hicn_get_buffer (b0)->type;
  hicn_ops_vft[type.l1]->rewrite_data (type, &hicn->protocol,
				       &(iface_ip->remote_addr), &(temp_addr),
				       iface->shared.pl_id);
}

static char *hicn_iface_ip4_output_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

static char *hicn_iface_ip6_output_error_strings[] = {
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
  u8 packet_data[128 - 1 * sizeof (u32)];
} hicn_iface_ip4_output_trace_t;

typedef enum
{
  HICN_IFACE_IP4_OUTPUT_NEXT_LOOKUP,
  HICN_IFACE_IP4_OUTPUT_NEXT_ERROR_DROP,
  HICN_IFACE_IP4_OUTPUT_N_NEXT,
} hicn_iface_ip4_output_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u8 packet_data[128 - 1 * sizeof (u32)];
} hicn_iface_ip6_output_trace_t;

typedef enum
{
  HICN_IFACE_IP6_OUTPUT_NEXT_LOOKUP,
  HICN_IFACE_IP6_OUTPUT_NEXT_ERROR_DROP,
  HICN_IFACE_IP6_OUTPUT_N_NEXT,
} hicn_iface_ip6_output_next_t;

#define ERROR_OUTPUT_IP4 HICN_IFACE_IP4_OUTPUT_NEXT_ERROR_DROP
#define ERROR_OUTPUT_IP6 HICN_IFACE_IP6_OUTPUT_NEXT_ERROR_DROP

#define NEXT_DATA_LOOKUP_IP4 HICN_IFACE_IP4_OUTPUT_NEXT_LOOKUP
#define NEXT_DATA_LOOKUP_IP6 HICN_IFACE_IP6_OUTPUT_NEXT_LOOKUP

#define HICN_REWRITE_DATA_IP4 hicn_rewrite_iface_data4
#define HICN_REWRITE_DATA_IP6 hicn_rewrite_iface_data6

#define TRACE_OUTPUT_PKT_IP4 hicn_iface_ip4_output_trace_t
#define TRACE_OUTPUT_PKT_IP6 hicn_iface_ip6_output_trace_t

#define iface_output_x1(ipv)                                            \
  do {                                                                  \
    vlib_buffer_t *b0;                                                  \
    u32 bi0;                                                            \
    u32 next0 = ERROR_OUTPUT_IP##ipv;                                   \
    hicn_face_t * face;                                                 \
									\
  /* Prefetch for next iteration. */					\
    if (n_left_from > 1)                                                \
      {                                                                 \
        vlib_buffer_t *b1;                                              \
        b1 = vlib_get_buffer (vm, from[1]);                             \
        CLIB_PREFETCH (b1, CLIB_CACHE_LINE_BYTES, STORE);               \
        CLIB_PREFETCH (b1->data, CLIB_CACHE_LINE_BYTES , STORE);	\
      }                                                                 \
    /* Dequeue a packet buffer */                                       \
    bi0 = from[0];                                                      \
    from += 1;                                                          \
    n_left_from -= 1;                                                   \
    to_next[0] = bi0;                                                   \
    to_next += 1;                                                       \
    n_left_to_next -= 1;                                                \
                                                                        \
    b0 = vlib_get_buffer (vm, bi0);                                     \
                                                                        \
    face =                                                              \
      hicn_dpoi_get_from_idx (vnet_buffer (b0)->ip.adj_index[VLIB_TX]); \
                                                                        \
    if (PREDICT_TRUE(face != NULL))                                     \
      {                                                                 \
        HICN_REWRITE_DATA_IP##ipv					\
          (vm, b0, face);                                               \
	next0 = NEXT_DATA_LOOKUP_IP##ipv;				\
	stats.pkts_data_count += 1;					\
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
  }while(0);                                                            \


#define iface_output_x2(ipv)                                            \
  do {                                                                  \
    vlib_buffer_t *b0, *b1;                                             \
    u32 bi0, bi1;                                                       \
    u32 next0 = ERROR_OUTPUT_IP##ipv;                                   \
    u32 next1 = ERROR_OUTPUT_IP##ipv;                                   \
    hicn_face_t *face0, *face1;                                         \
                                                                        \
    /* Prefetch for next iteration. */                                  \
    {                                                                   \
      vlib_buffer_t *b2, *b3;                                           \
      b2 = vlib_get_buffer (vm, from[2]);                               \
      b3 = vlib_get_buffer (vm, from[3]);                               \
      CLIB_PREFETCH (b2, CLIB_CACHE_LINE_BYTES, STORE);                 \
      CLIB_PREFETCH (b3, CLIB_CACHE_LINE_BYTES, STORE);                 \
      CLIB_PREFETCH (b2->data, CLIB_CACHE_LINE_BYTES , STORE);		\
      CLIB_PREFETCH (b3->data, CLIB_CACHE_LINE_BYTES , STORE);		\
    }                                                                   \
                                                                        \
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
                                                                        \
    face0 =                                                             \
      hicn_dpoi_get_from_idx (vnet_buffer (b0)->ip.adj_index[VLIB_TX]); \
    face1 =                                                             \
      hicn_dpoi_get_from_idx (vnet_buffer (b1)->ip.adj_index[VLIB_TX]); \
                                                                        \
    if (PREDICT_TRUE(face0 != NULL))                                    \
      {                                                                 \
        HICN_REWRITE_DATA_IP##ipv					\
          (vm, b0, face0);                                              \
	next0 = NEXT_DATA_LOOKUP_IP##ipv;				\
	stats.pkts_data_count += 1;					\
      }                                                                 \
                                                                        \
    if (PREDICT_TRUE(face1 != NULL))                                    \
      {                                                                 \
        HICN_REWRITE_DATA_IP##ipv					\
          (vm, b1, face1);                                              \
        next1 = NEXT_DATA_LOOKUP_IP##ipv;				\
	stats.pkts_data_count += 1;					\
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
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&          \
                       (b1->flags & VLIB_BUFFER_IS_TRACED)))            \
      {                                                                 \
        TRACE_OUTPUT_PKT_IP##ipv *t =                                   \
          vlib_add_trace (vm, node, b1, sizeof (*t));                   \
        t->pkt_type = HICN_PKT_TYPE_INTEREST;                           \
        t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];        \
        t->next_index = next1;                                          \
	clib_memcpy_fast (t->packet_data,				\
			  vlib_buffer_get_current (b1),			\
			  sizeof (t->packet_data));			\
      }                                                                 \
                                                                        \
                                                                        \
    /* Verify speculative enqueue, maybe switch current next frame */   \
    vlib_validate_buffer_enqueue_x2 (vm, node, next_index,              \
                                     to_next, n_left_to_next,           \
                                     bi0, bi1, next0, next1);           \
  }while(0);                                                            \



static uword
hicn_iface_ip4_output_node_fn (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };

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
hicn_iface_ip4_output_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_iface_ip4_output_trace_t *t =
    va_arg (*args, hicn_iface_ip4_output_trace_t *);

  s = format (s, "IFACE_IP4_OUTPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
		(int) t->pkt_type, t->sw_if_index, t->next_index, format_ip4_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_iface_ip4_output_node) =
{
  .function = hicn_iface_ip4_output_node_fn,
  .name = "hicn-iface-ip4-output",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_iface_ip4_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_iface_ip4_output_error_strings),
  .error_strings = hicn_iface_ip4_output_error_strings,
  .n_next_nodes = HICN_IFACE_IP4_OUTPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN_IFACE_IP4_OUTPUT_NEXT_LOOKUP] = "ip4-lookup",
    [HICN_IFACE_IP4_OUTPUT_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */


static uword
hicn_iface_ip6_output_node_fn (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index;
  vl_api_hicn_api_node_stats_get_reply_t stats = { 0 };

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
hicn_iface_ip6_output_format_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_iface_ip6_output_trace_t *t =
    va_arg (*args, hicn_iface_ip6_output_trace_t *);

  s = format (s, "IFACE_IP6_OUTPUT: pkt: %d, sw_if_index %d, next index %d\n%U",
		(int) t->pkt_type, t->sw_if_index, t->next_index, format_ip6_header, t->packet_data, sizeof (t->packet_data));
  return (s);
}

/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_iface_ip6_output_node) =
{
  .function = hicn_iface_ip6_output_node_fn,
  .name = "hicn-iface-ip6-output",
  .vector_size =  sizeof (u32),
  .format_trace = hicn_iface_ip6_output_format_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hicn_iface_ip6_output_error_strings),
  .error_strings = hicn_iface_ip6_output_error_strings,
  .n_next_nodes = HICN_IFACE_IP6_OUTPUT_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICN_IFACE_IP6_OUTPUT_NEXT_LOOKUP] = "ip6-lookup",
    [HICN_IFACE_IP6_OUTPUT_NEXT_ERROR_DROP] = "error-drop",
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
