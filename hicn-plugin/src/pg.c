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
#include <vnet/pg/pg.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include "hicn.h"
#include "pg.h"
#include "parser.h"
#include "infra.h"

/* Registration struct for a graph node */
vlib_node_registration_t hicn_pg_interest_node;
vlib_node_registration_t hicn_pg_data_node;

/* Stats, which end up called "error" even though they aren't... */
#define foreach_hicnpg_error                                  \
  _(PROCESSED, "hICN PG packets processed")                   \
  _(DROPPED, "hICN PG packets dropped")                       \
  _(INTEREST_MSGS_GENERATED, "hICN PG Interests generated")   \
  _(CONTENT_MSGS_RECEIVED, "hICN PG Content msgs received")

typedef enum
{
#define _(sym,str) HICNPG_ERROR_##sym,
  foreach_hicnpg_error
#undef _
    HICNPG_N_ERROR,
} hicnpg_error_t;

static char *hicnpg_error_strings[] = {
#define _(sym,string) string,
  foreach_hicnpg_error
#undef _
};

/*
 * Next graph nodes, which reference the list in the actual registration
 * block below
 */
typedef enum
{
  HICNPG_INTEREST_NEXT_V4_LOOKUP,
  HICNPG_INTEREST_NEXT_V6_LOOKUP,
  HICNPG_INTEREST_NEXT_DROP,
  HICNPG_N_NEXT,
} hicnpg_interest_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u16 msg_type;
} hicnpg_trace_t;

hicnpg_main_t hicnpg_main = {
  .index = (u32) 0,
  .index_ifaces = (u32) 1,
  .max_seq_number = (u32) ~ 0,
  .interest_lifetime = 4,
  .n_flows = (u32) 0,
  .n_ifaces = (u32) 1,
};

hicnpg_server_main_t hicnpg_server_main = {
  .node_index = 0,
};

/* packet trace format function */
static u8 *
format_hicnpg_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicnpg_trace_t *t = va_arg (*args, hicnpg_trace_t *);

  s = format (s, "HICNPG: pkt: %d, msg %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, (int) t->msg_type,
	      t->sw_if_index, t->next_index);
  return (s);
}

always_inline void
hicn_rewrite_interestv4 (vlib_main_t * vm, vlib_buffer_t * b0, u32 seq_number,
			 u16 lifetime, u32 next_flow, u32 iface);

always_inline void
hicn_rewrite_interestv6 (vlib_main_t * vm, vlib_buffer_t * b0, u32 seq_number,
			 u16 lifetime, u32 next_flow, u32 iface);

always_inline void
convert_interest_to_data_v4 (vlib_main_t * vm, vlib_buffer_t * b0,
			     vlib_buffer_t * rb, u32 bi0);

always_inline void
convert_interest_to_data_v6 (vlib_main_t * vm, vlib_buffer_t * b0,
			     vlib_buffer_t * rb, u32 bi0);

always_inline void
calculate_tcp_checksum_v4 (vlib_main_t * vm, vlib_buffer_t * b0);

always_inline void
calculate_tcp_checksum_v6 (vlib_main_t * vm, vlib_buffer_t * b0);
/*
 * Node function for the icn packet-generator client. The goal here is to
 * manipulate/tweak a stream of packets that have been injected by the vpp
 * packet generator to generate icn request traffic.
 */
static uword
hicnpg_client_interest_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  hicnpg_interest_next_t next_index;
  u32 pkts_processed = 0, pkts_dropped = 0;
  u32 interest_msgs_generated = 0;
  u32 bi0, bi1;
  vlib_buffer_t *b0, *b1;
  u8 pkt_type0 = 0, pkt_type1 = 0;
  u16 msg_type0 = 0, msg_type1 = 0;
  hicn_header_t *hicn0 = NULL, *hicn1 = NULL;
  hicn_name_t name0, name1;
  u16 namelen0, namelen1;
  hicnpg_main_t *hpgm = &hicnpg_main;
  int iface = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = HICNPG_INTEREST_NEXT_DROP;
	  u32 next1 = HICNPG_INTEREST_NEXT_DROP;
	  u32 sw_if_index0 = ~0, sw_if_index1 = ~0;
	  u8 isv6_0;
	  u8 isv6_1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, (2 * CLIB_CACHE_LINE_BYTES), STORE);
	    CLIB_PREFETCH (p3->data, (2 * CLIB_CACHE_LINE_BYTES), STORE);
	  }

	  /*
	   * speculatively enqueue b0 and b1 to the current
	   * next frame
	   */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  /* Check icn packets, locate names */
	  if (hicn_interest_parse_pkt (b0, &name0, &namelen0, &hicn0, &isv6_0)
	      == HICN_ERROR_NONE)
	    {
	      /* this node grabs only interests */

	      /* Increment the appropriate message counter */
	      interest_msgs_generated++;

	      iface = (hpgm->index_ifaces % hpgm->n_ifaces);
	      /* Rewrite and send */
	      isv6_0 ? hicn_rewrite_interestv6 (vm, b0,
						(hpgm->index /
						 hpgm->n_flows) %
						hpgm->max_seq_number,
						hpgm->interest_lifetime,
						hpgm->index % hpgm->n_flows,
						iface) :
		hicn_rewrite_interestv4 (vm, b0,
					 (hpgm->index / hpgm->n_flows) %
					 hpgm->max_seq_number,
					 hpgm->interest_lifetime,
					 hpgm->index % hpgm->n_flows, iface);

	      hpgm->index_ifaces++;
	      if (iface == (hpgm->n_ifaces - 1))
		hpgm->index++;

	      next0 =
		isv6_0 ? HICNPG_INTEREST_NEXT_V6_LOOKUP :
		HICNPG_INTEREST_NEXT_V4_LOOKUP;
	    }
	  if (hicn_interest_parse_pkt (b1, &name1, &namelen1, &hicn1, &isv6_1)
	      == HICN_ERROR_NONE)
	    {
	      /* this node grabs only interests */

	      /* Increment the appropriate message counter */
	      interest_msgs_generated++;

	      iface = (hpgm->index_ifaces % hpgm->n_ifaces);
	      /* Rewrite and send */
	      isv6_1 ? hicn_rewrite_interestv6 (vm, b1,
						(hpgm->index /
						 hpgm->n_flows) %
						hpgm->max_seq_number,
						hpgm->interest_lifetime,
						hpgm->index % hpgm->n_flows,
						iface) :
		hicn_rewrite_interestv4 (vm, b1,
					 (hpgm->index / hpgm->n_flows) %
					 hpgm->max_seq_number,
					 hpgm->interest_lifetime,
					 hpgm->index % hpgm->n_flows, iface);

	      hpgm->index_ifaces++;
	      if (iface == (hpgm->n_ifaces - 1))
		hpgm->index++;

	      next1 =
		isv6_1 ? HICNPG_INTEREST_NEXT_V6_LOOKUP :
		HICNPG_INTEREST_NEXT_V4_LOOKUP;
	    }
	  /* Send pkt to next node */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;
	  vnet_buffer (b1)->sw_if_index[VLIB_TX] = ~0;

	  pkts_processed += 2;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  hicnpg_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->pkt_type = pkt_type0;
		  t->msg_type = msg_type0;
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  hicnpg_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->pkt_type = pkt_type1;
		  t->msg_type = msg_type1;
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		}
	    }
	  if (next0 == HICNPG_INTEREST_NEXT_DROP)
	    {
	      pkts_dropped++;
	    }
	  if (next1 == HICNPG_INTEREST_NEXT_DROP)
	    {
	      pkts_dropped++;
	    }
	  /*
	   * verify speculative enqueues, maybe switch current
	   * next frame
	   */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 next0 = HICNPG_INTEREST_NEXT_DROP;
	  u32 sw_if_index0;
	  u8 isv6_0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* Check icn packets, locate names */
	  if (hicn_interest_parse_pkt (b0, &name0, &namelen0, &hicn0, &isv6_0)
	      == HICN_ERROR_NONE)
	    {
	      /* this node grabs only interests */

	      /* Increment the appropriate message counter */
	      interest_msgs_generated++;

	      iface = (hpgm->index_ifaces % hpgm->n_ifaces);

	      /* Rewrite and send */
	      isv6_0 ? hicn_rewrite_interestv6 (vm, b0,
						(hpgm->index /
						 hpgm->n_flows) %
						hpgm->max_seq_number,
						hpgm->interest_lifetime,
						hpgm->index % hpgm->n_flows,
						iface) :
		hicn_rewrite_interestv4 (vm, b0,
					 (hpgm->index / hpgm->n_flows) %
					 hpgm->max_seq_number,
					 hpgm->interest_lifetime,
					 hpgm->index % hpgm->n_flows, iface);

	      hpgm->index_ifaces++;
	      if (iface == (hpgm->n_ifaces - 1))
		hpgm->index++;

	      next0 =
		isv6_0 ? HICNPG_INTEREST_NEXT_V6_LOOKUP :
		HICNPG_INTEREST_NEXT_V4_LOOKUP;
	    }
	  /* Send pkt to ip lookup */
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicnpg_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pkt_type = pkt_type0;
	      t->msg_type = msg_type0;
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	    }
	  pkts_processed += 1;

	  if (next0 == HICNPG_INTEREST_NEXT_DROP)
	    {
	      pkts_dropped++;
	    }
	  /*
	   * verify speculative enqueue, maybe switch current
	   * next frame
	   */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, hicn_pg_interest_node.index,
			       HICNPG_ERROR_PROCESSED, pkts_processed);
  vlib_node_increment_counter (vm, hicn_pg_interest_node.index,
			       HICNPG_ERROR_DROPPED, pkts_dropped);
  vlib_node_increment_counter (vm, hicn_pg_interest_node.index,
			       HICNPG_ERROR_INTEREST_MSGS_GENERATED,
			       interest_msgs_generated);

  return (frame->n_vectors);
}

void
hicn_rewrite_interestv4 (vlib_main_t * vm, vlib_buffer_t * b0, u32 seq_number,
			 u16 interest_lifetime, u32 next_flow, u32 iface)
{
  hicn_header_t *h0 = vlib_buffer_get_current (b0);

  /* Generate the right src and dst corresponding to flow and iface */
  ip46_address_t src_addr = {
    .ip4 = hicnpg_main.pgen_clt_src_addr.ip4,
  };
  hicn_name_t dst_name = {
    .ip4.prefix_as_ip4 = hicnpg_main.pgen_clt_hicn_name.ip4,
    .ip4.suffix = seq_number,
  };

  src_addr.ip4.as_u32 += clib_host_to_net_u32 (iface);
  dst_name.ip4.prefix_as_ip4.as_u32 += clib_net_to_host_u32 (next_flow);

  /* Update locator and name */
  hicn_type_t type = hicn_get_buffer (b0)->type;
  HICN_OPS4->set_interest_locator (type, &h0->protocol, &src_addr);
  HICN_OPS4->set_interest_name (type, &h0->protocol, &dst_name);

  /* Update lifetime  (currently L4 checksum is not updated) */
  HICN_OPS4->set_lifetime (type, &h0->protocol, interest_lifetime);

  /* Update checksums */
  HICN_OPS4->update_checksums (type, &h0->protocol, 0, 0);
}

/**
 * @brief Rewrite the IPv6 header as the next generated packet
 *
 * Set up a name prefix
 *  - etiher generate interest in which the name varies only after the prefix
 *  (inc : seq_number), then the flow acts on the prefix (CHECK)
 *  seq_number => TCP, FLOW =>
 *
 *  SRC : pgen_clt_src_addr.ip6 DST = generate name (pgen_clt_hicn_name.ip6)
 *  ffff:ffff:ffff:ffff         ffff:ffff:ffff:ffff
 *                 \__/                        \__/
 *                 +iface                      + flow
 *  Source is used to emulate different consumers.
 *    FIXME iface is ill-named, better name it consumer id
 *  Destination is used to iterate on the content.
 */
void
hicn_rewrite_interestv6 (vlib_main_t * vm, vlib_buffer_t * b0, u32 seq_number,
			 u16 interest_lifetime, u32 next_flow, u32 iface)
{
  hicn_header_t *h0 = vlib_buffer_get_current (b0);

  /* Generate the right src and dst corresponding to flow and iface */
  ip46_address_t src_addr = {
    .ip6 = hicnpg_main.pgen_clt_src_addr.ip6,
  };
  hicn_name_t dst_name = {
    .ip6.prefix_as_ip6 = hicnpg_main.pgen_clt_hicn_name.ip6,
    .ip6.suffix = seq_number,
  };
  src_addr.ip6.as_u32[3] += clib_host_to_net_u32 (iface);
  dst_name.ip6.prefix_as_ip6.as_u32[3] += clib_net_to_host_u32 (next_flow);

  /* Update locator and name */
  hicn_type_t type = hicn_get_buffer (b0)->type;
  HICN_OPS6->set_interest_locator (type, &h0->protocol, &src_addr);
  HICN_OPS6->set_interest_name (type, &h0->protocol, &dst_name);

  /* Update lifetime */
  HICN_OPS6->set_lifetime (type, &h0->protocol, interest_lifetime);

  /* Update checksums */
  calculate_tcp_checksum_v6 (vm, b0);
}



void
calculate_tcp_checksum_v4 (vlib_main_t * vm, vlib_buffer_t * b0)
{
  ip4_header_t *ip0;
  tcp_header_t *tcp0;
  ip_csum_t sum0;
  u32 tcp_len0;

  ip0 = (ip4_header_t *) (vlib_buffer_get_current (b0));
  tcp0 =
    (tcp_header_t *) (vlib_buffer_get_current (b0) + sizeof (ip4_header_t));
  tcp_len0 = clib_net_to_host_u16 (ip0->length) - sizeof (ip4_header_t);

  /* Initialize checksum with header. */
  if (BITS (sum0) == 32)
    {
      sum0 = clib_mem_unaligned (&ip0->src_address, u32);
      sum0 =
	ip_csum_with_carry (sum0,
			    clib_mem_unaligned (&ip0->dst_address, u32));
    }
  else
    sum0 = clib_mem_unaligned (&ip0->src_address, u64);

  sum0 = ip_csum_with_carry
    (sum0, clib_host_to_net_u32 (tcp_len0 + (ip0->protocol << 16)));

  /* Invalidate possibly old checksum. */
  tcp0->checksum = 0;

  u32 tcp_offset = sizeof (ip4_header_t);
  sum0 = ip_incremental_checksum_buffer (vm, b0, tcp_offset, tcp_len0, sum0);

  tcp0->checksum = ~ip_csum_fold (sum0);
}

void
calculate_tcp_checksum_v6 (vlib_main_t * vm, vlib_buffer_t * b0)
{
  ip6_header_t *ip0;
  tcp_header_t *tcp0;
  ip_csum_t sum0;
  u32 tcp_len0;

  ip0 = (ip6_header_t *) (vlib_buffer_get_current (b0));
  tcp0 =
    (tcp_header_t *) (vlib_buffer_get_current (b0) + sizeof (ip6_header_t));
  tcp_len0 = clib_net_to_host_u16 (ip0->payload_length);

  /* Initialize checksum with header. */
  if (BITS (sum0) == 32)
    {
      sum0 = clib_mem_unaligned (&ip0->src_address, u32);
      sum0 =
	ip_csum_with_carry (sum0,
			    clib_mem_unaligned (&ip0->dst_address, u32));
    }
  else
    sum0 = clib_mem_unaligned (&ip0->src_address, u64);

  sum0 = ip_csum_with_carry
    (sum0, clib_host_to_net_u32 (tcp_len0 + (ip0->protocol << 16)));

  /* Invalidate possibly old checksum. */
  tcp0->checksum = 0;

  u32 tcp_offset = sizeof (ip6_header_t);
  sum0 = ip_incremental_checksum_buffer (vm, b0, tcp_offset, tcp_len0, sum0);

  tcp0->checksum = ~ip_csum_fold (sum0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn_pg_interest_node) ={
  .function = hicnpg_client_interest_node_fn,
  .name = "hicnpg-interest",
  .vector_size = sizeof(u32),
  .format_trace = format_hicnpg_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicnpg_error_strings),
  .error_strings = hicnpg_error_strings,
  .n_next_nodes = HICNPG_N_NEXT,
  .next_nodes =
  {
    [HICNPG_INTEREST_NEXT_V4_LOOKUP] = "ip4-lookup",
    [HICNPG_INTEREST_NEXT_V6_LOOKUP] = "ip6-lookup",
    [HICNPG_INTEREST_NEXT_DROP] = "error-drop"
  },
};
/* *INDENT-ON* */

/*
 * Next graph nodes, which reference the list in the actual registration
 * block below
 */
typedef enum
{
  HICNPG_DATA_NEXT_DROP,
  HICNPG_DATA_N_NEXT,
} hicnpg_data_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u16 msg_type;
} icnpg_data_trace_t;

/* packet trace format function */
static u8 *
format_hicnpg_data_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicnpg_trace_t *t = va_arg (*args, hicnpg_trace_t *);

  s = format (s, "HICNPG: pkt: %d, msg %d, sw_if_index %d, next index %d",
	      (int) t->pkt_type, (int) t->msg_type,
	      t->sw_if_index, t->next_index);
  return (s);
}


/*
 * Node function for the icn packet-generator client. The goal here is to
 * manipulate/tweak a stream of packets that have been injected by the vpp
 * packet generator to generate icn request traffic.
 */
static uword
hicnpg_client_data_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  hicnpg_data_next_t next_index;
  u32 pkts_processed = 0;
  u32 content_msgs_received = 0;
  u32 bi0, bi1;
  vlib_buffer_t *b0, *b1;
  u8 pkt_type0 = 0, pkt_type1 = 0;
  u16 msg_type0 = 1, msg_type1 = 1;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = HICNPG_DATA_NEXT_DROP;
	  u32 next1 = HICNPG_DATA_NEXT_DROP;
	  u32 sw_if_index0, sw_if_index1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, (2 * CLIB_CACHE_LINE_BYTES), STORE);
	    CLIB_PREFETCH (p3->data, (2 * CLIB_CACHE_LINE_BYTES), STORE);
	  }

	  /*
	   * speculatively enqueue b0 and b1 to the current
	   * next frame
	   */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  /* Increment a counter */
	  content_msgs_received += 2;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  icnpg_data_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->pkt_type = pkt_type0;
		  t->msg_type = msg_type0;
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  icnpg_data_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->pkt_type = pkt_type1;
		  t->msg_type = msg_type1;
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		}
	    }
	  pkts_processed += 2;
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 next0 = HICNPG_DATA_NEXT_DROP;
	  u32 sw_if_index0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  /* Increment a counter */
	  content_msgs_received++;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      icnpg_data_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pkt_type = pkt_type0;
	      t->msg_type = msg_type0;
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	    }
	  pkts_processed++;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, hicn_pg_data_node.index,
			       HICNPG_ERROR_PROCESSED, pkts_processed);
  vlib_node_increment_counter (vm, hicn_pg_data_node.index,
			       HICNPG_ERROR_CONTENT_MSGS_RECEIVED,
			       content_msgs_received);
  return (frame->n_vectors);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn_pg_data_node) =
{
  .function = hicnpg_client_data_node_fn,
  .name = "hicnpg-data",
  .vector_size = sizeof(u32),
  .format_trace = format_hicnpg_data_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(hicnpg_error_strings),
  .error_strings = hicnpg_error_strings,
  .n_next_nodes = HICNPG_DATA_N_NEXT,
  .next_nodes =
  {
    [HICNPG_DATA_NEXT_DROP] = "error-drop"
  },
};
/* *INDENT-ON* */

/*
 * End of packet-generator client node
 */

/*
 * Beginning of packet-generation server node
 */

/* Registration struct for a graph node */
vlib_node_registration_t hicn_pg_server_node;

/* Stats, which end up called "error" even though they aren't... */
#define foreach_icnpg_server_error		\
_(PROCESSED, "hICN PG Server packets processed")	\
_(DROPPED, "hICN PG Server packets dropped")

typedef enum
{
#define _(sym,str) HICNPG_SERVER_ERROR_##sym,
  foreach_icnpg_server_error
#undef _
    HICNPG_SERVER_N_ERROR,
} icnpg_server_error_t;

static char *icnpg_server_error_strings[] = {
#define _(sym,string) string,
  foreach_icnpg_server_error
#undef _
};

/*
 * Next graph nodes, which reference the list in the actual registration
 * block below
 */
typedef enum
{
  HICNPG_SERVER_NEXT_V4_LOOKUP,
  HICNPG_SERVER_NEXT_V6_LOOKUP,
  HICNPG_SERVER_NEXT_DROP,
  HICNPG_SERVER_N_NEXT,
} icnpg_server_next_t;

/* Trace context struct */
typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 pkt_type;
  u16 msg_type;
} hicnpg_server_trace_t;

/* packet trace format function */
static u8 *
format_icnpg_server_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicnpg_server_trace_t *t = va_arg (*args, hicnpg_server_trace_t *);

  s =
    format (s,
	    "HICNPG SERVER: pkt: %d, msg %d, sw_if_index %d, next index %d",
	    (int) t->pkt_type, (int) t->msg_type, t->sw_if_index,
	    t->next_index);
  return (s);
}

/*
 * Node function for the icn packet-generator server.
 */
static uword
hicnpg_node_server_fn (vlib_main_t * vm,
		       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  icnpg_server_next_t next_index;
  u32 pkts_processed = 0, pkts_dropped = 0;
  u32 bi0, bi1;
  vlib_buffer_t *b0, *b1;
  u8 pkt_type0 = 0, pkt_type1 = 0;
  u16 msg_type0 = 0, msg_type1 = 0;
  hicn_header_t *hicn0 = NULL, *hicn1 = NULL;
  hicn_name_t name0, name1;
  u16 namelen0, namelen1;

  hicnpg_server_main_t *hpgsm = &hicnpg_server_main;

  from = vlib_frame_vector_args (frame);

  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);


      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 next0 = HICNPG_SERVER_NEXT_DROP;
	  u32 next1 = HICNPG_SERVER_NEXT_DROP;
	  u8 isv6_0 = 0;
	  u8 isv6_1 = 0;
	  u32 sw_if_index0, sw_if_index1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, (2 * CLIB_CACHE_LINE_BYTES), STORE);
	    CLIB_PREFETCH (p3->data, (2 * CLIB_CACHE_LINE_BYTES), STORE);
	  }

	  /*
	   * speculatively enqueue b0 and b1 to the current
	   * next frame
	   */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

	  if (hicn_interest_parse_pkt (b0, &name0, &namelen0, &hicn0, &isv6_0)
	      == HICN_ERROR_NONE)
	    {
	      /* this node grabs only interests */
	      vlib_buffer_t *rb = NULL;
	      rb = vlib_get_buffer (vm, hpgsm->pgen_svr_buffer_idx);

	      isv6_0 ? convert_interest_to_data_v6 (vm, b0, rb,
						    bi0) :
		convert_interest_to_data_v4 (vm, b0, rb, bi0);

	      next0 =
		isv6_0 ? HICNPG_SERVER_NEXT_V6_LOOKUP :
		HICNPG_SERVER_NEXT_V4_LOOKUP;
	    }
	  if (hicn_interest_parse_pkt (b1, &name1, &namelen1, &hicn1, &isv6_1)
	      == HICN_ERROR_NONE)
	    {
	      /* this node grabs only interests */
	      vlib_buffer_t *rb = NULL;
	      rb = vlib_get_buffer (vm, hpgsm->pgen_svr_buffer_idx);

	      isv6_1 ? convert_interest_to_data_v6 (vm, b1, rb,
						    bi1) :
		convert_interest_to_data_v4 (vm, b1, rb, bi1);

	      next1 =
		isv6_1 ? HICNPG_SERVER_NEXT_V6_LOOKUP :
		HICNPG_SERVER_NEXT_V4_LOOKUP;
	    }
	  pkts_processed += 2;

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
	      if (b0->flags & VLIB_BUFFER_IS_TRACED)
		{
		  hicnpg_server_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->pkt_type = pkt_type0;
		  t->msg_type = msg_type0;
		  t->sw_if_index = sw_if_index0;
		  t->next_index = next0;
		}
	      if (b1->flags & VLIB_BUFFER_IS_TRACED)
		{
		  hicnpg_server_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->pkt_type = pkt_type1;
		  t->msg_type = msg_type1;
		  t->sw_if_index = sw_if_index1;
		  t->next_index = next1;
		}
	    }
	  if (next0 == HICNPG_SERVER_NEXT_DROP)
	    {
	      pkts_dropped++;
	    }
	  if (next1 == HICNPG_SERVER_NEXT_DROP)
	    {
	      pkts_dropped++;
	    }
	  /*
	   * verify speculative enqueues, maybe switch current
	   * next frame
	   */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 next0 = HICNPG_SERVER_NEXT_DROP;
	  u32 sw_if_index0 = ~0;
	  u8 isv6_0 = 0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];


	  if (hicn_interest_parse_pkt (b0, &name0, &namelen0, &hicn0, &isv6_0)
	      == HICN_ERROR_NONE)
	    {
	      /* this node grabs only interests */
	      vlib_buffer_t *rb = NULL;
	      rb = vlib_get_buffer (vm, hpgsm->pgen_svr_buffer_idx);

	      isv6_0 ? convert_interest_to_data_v6 (vm, b0, rb,
						    bi0) :
		convert_interest_to_data_v4 (vm, b0, rb, bi0);

	      next0 =
		isv6_0 ? HICNPG_SERVER_NEXT_V6_LOOKUP :
		HICNPG_SERVER_NEXT_V4_LOOKUP;
	    }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hicnpg_server_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->pkt_type = pkt_type0;
	      t->msg_type = msg_type0;
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	    }
	  pkts_processed += 1;

	  if (next0 == HICNPG_SERVER_NEXT_DROP)
	    {
	      pkts_dropped++;
	    }
	  /*
	   * verify speculative enqueue, maybe switch current
	   * next frame
	   */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, hicn_pg_server_node.index,
			       HICNPG_SERVER_ERROR_PROCESSED, pkts_processed);
  vlib_node_increment_counter (vm, hicn_pg_server_node.index,
			       HICNPG_SERVER_ERROR_DROPPED, pkts_dropped);

  return (frame->n_vectors);
}

void
convert_interest_to_data_v4 (vlib_main_t * vm, vlib_buffer_t * b0,
			     vlib_buffer_t * rb, u32 bi0)
{
  hicn_header_t *h0 = vlib_buffer_get_current (b0);

  /* Get the packet length */
  u16 pkt_len = clib_net_to_host_u16 (h0->v4.ip.len);

  /*
   * Rule of thumb: We want the size of the IP packet to be <= 1500 bytes
   */
  u16 bytes_to_copy = rb->current_length;
  if ((bytes_to_copy + pkt_len) > 1500)
    {
      bytes_to_copy = 1500 - pkt_len;
    }
  /* Add content to the data packet */
  vlib_buffer_add_data (vm, &bi0, rb->data, bytes_to_copy);

  b0 = vlib_get_buffer (vm, bi0);

  h0 = vlib_buffer_get_current (b0);

  ip4_address_t src_addr = h0->v4.ip.saddr;
  h0->v4.ip.saddr = h0->v4.ip.daddr;
  h0->v4.ip.daddr = src_addr;

  h0->v4.ip.len = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
  h0->v4.ip.csum = ip4_header_checksum ((ip4_header_t *) & (h0->v4.ip));
  calculate_tcp_checksum_v4 (vm, b0);
}

void
convert_interest_to_data_v6 (vlib_main_t * vm, vlib_buffer_t * b0,
			     vlib_buffer_t * rb, u32 bi0)
{
  hicn_header_t *h0 = vlib_buffer_get_current (b0);

  /* Get the packet length */
  uint16_t pkt_len =
    clib_net_to_host_u16 (h0->v6.ip.len) + sizeof (ip6_header_t);

  /*
   * Figure out how many bytes we can add to the content
   *
   * Rule of thumb: We want the size of the IP packet to be <= 1400 bytes
   */
  u16 bytes_to_copy = rb->current_length;
  if ((bytes_to_copy + pkt_len) > 1500)
    {
      bytes_to_copy = 1500 - pkt_len;
    }
  /* Add content to the data packet */
  vlib_buffer_add_data (vm, &bi0, rb->data, bytes_to_copy);

  b0 = vlib_get_buffer (vm, bi0);

  h0 = vlib_buffer_get_current (b0);
  ip6_address_t src_addr = h0->v6.ip.saddr;
  h0->v6.ip.saddr = h0->v6.ip.daddr;
  h0->v6.ip.daddr = src_addr;

  h0->v6.ip.len = clib_host_to_net_u16 (vlib_buffer_length_in_chain
					(vm, b0) - sizeof (ip6_header_t));
  h0->v6.tcp.data_offset_and_reserved |= 0x0f;
  h0->v6.tcp.urg_ptr = htons (0xffff);

  calculate_tcp_checksum_v6 (vm, b0);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn_pg_server_node) =
{
  .function = hicnpg_node_server_fn,
  .name = "hicnpg-server",
  .vector_size = sizeof(u32),
  .format_trace = format_icnpg_server_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(icnpg_server_error_strings),
  .error_strings = icnpg_server_error_strings,
  .n_next_nodes = HICNPG_SERVER_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [HICNPG_SERVER_NEXT_V4_LOOKUP] = "ip4-lookup",
    [HICNPG_SERVER_NEXT_V6_LOOKUP] = "ip6-lookup",
    [HICNPG_SERVER_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT(hicn_pg_server_ip6, static)=
  {
   .arc_name = "ip6-unicast",
   .node_name = "hicnpg-server",
   .runs_before = VNET_FEATURES("ip6-inacl"),
  };
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT(hicn_pg_server_ip4, static)=
  {
   .arc_name = "ip4-unicast",
   .node_name = "hicnpg-server",
   .runs_before = VNET_FEATURES("ip4-inacl"),
  };
/* *INDENT-ON* */

/*
 * End of packet-generator server node
 */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
