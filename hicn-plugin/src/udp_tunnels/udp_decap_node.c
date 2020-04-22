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
#include <vnet/fib/fib_table.h>

#include "udp_tunnel.h"
#include "../mgmt.h"
#include "../hicn.h"
#include "../strategy_dpo_ctx.h"

/**
 * @File
 *
 * Definition of the nodes for ip incomplete faces.
 */

vlib_node_registration_t udp_decap_node;

static char *udp_decap_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

/* Trace context struct */
typedef enum
{
  UDP4_DECAP_NEXT_LOOKUP_IP4,
  UDP4_DECAP_N_NEXT,
} udp4_decap_next_t;

typedef enum
{
 UDP6_DECAP_NEXT_LOOKUP_IP6,
 UDP6_DECAP_N_NEXT,
} udp6_decap_next_t;

typedef struct udp4_decap_trace_t_
{
  ip4_header_t ip;
  udp_header_t udp;
} udp4_decap_trace_t;

typedef struct udp6_decap_trace_t_
{
  ip6_header_t ip;
  udp_header_t udp;
} udp6_decap_trace_t;

typedef struct udp_decap_trace_t_
{
  union
  {
    udp4_decap_trace_t udp4;
    udp6_decap_trace_t udp6;
  };

  u8 isv6;
  u8 ishicn;
} udp_decap_trace_t;


static u8 *
format_udp_decap_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  udp_decap_trace_t *t;

  t = va_arg (*args, udp_decap_trace_t *);

  if (t->isv6)
    {
      s = format (s, "%U\n  %U \n %s",
                  format_ip4_header, &t->udp6.ip, sizeof (t->udp6.ip),
                  format_udp_header, &t->udp6.udp, sizeof (t->udp6.udp),
                  t->ishicn ? "hICN udp tunnel" : "");
    }
  else
    {
      s = format (s, "%U\n  %U \n %s",
                  format_ip4_header, &t->udp4.ip, sizeof (t->udp4.ip),
                  format_udp_header, &t->udp4.udp, sizeof (t->udp4.udp),
                  t->ishicn ? "hICN udp tunnel" : "");
    }
  return (s);
}

static_always_inline void
udp_decap_trace_buffer (vlib_main_t * vm, vlib_node_runtime_t * node,
                        u8 isv6, vlib_buffer_t * b)
{
  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
		     (b->flags & VLIB_BUFFER_IS_TRACED)))
    {
      udp_decap_trace_t *t =
	vlib_add_trace (vm, node, b, sizeof (*t));
      t->isv6 = isv6;
      hicn_buffer_t *hb = hicn_get_buffer(b);

      if (isv6)
        {
          clib_memcpy(&(t->udp6.udp), vlib_buffer_get_current(b) + sizeof(ip6_header_t), sizeof(udp_header_t));
          clib_memcpy(&(t->udp6.ip), vlib_buffer_get_current(b), sizeof(ip6_header_t));
          t->ishicn = hb->flags & HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;
        }
      else
        {
          clib_memcpy(&(t->udp4.udp), vlib_buffer_get_current(b) + sizeof(ip4_header_t), sizeof(udp_header_t));
          clib_memcpy(&(t->udp4.ip), vlib_buffer_get_current(b), sizeof(ip4_header_t));
          t->ishicn = hb->flags & HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;
        }
    }
}

static uword
udp4_decap_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                   vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop, X2 */
      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
          vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 bi0, bi1, bi2, bi3;
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

          u8 advance = sizeof(ip4_header_t) + sizeof(udp_header_t);

          vlib_buffer_advance(b0, -advance);
          vlib_buffer_advance(b1, -advance);
          vlib_buffer_advance(b2, -advance);
          vlib_buffer_advance(b3, -advance);

          u8 *ptr0 = vlib_buffer_get_current (b0);
          u8 *ptr1 = vlib_buffer_get_current (b0);
          u8 *ptr2 = vlib_buffer_get_current (b0);
          u8 *ptr3 = vlib_buffer_get_current (b0);

          ip46_address_t src0 = {0};
          ip46_address_t src1 = {0};
          ip46_address_t src2 = {0};
          ip46_address_t src3 = {0};

          ip46_address_t dst0 = {0};
          ip46_address_t dst1 = {0};
          ip46_address_t dst2 = {0};
          ip46_address_t dst3 = {0};

          udp_header_t * udp0 = NULL;
          udp_header_t * udp1 = NULL;
          udp_header_t * udp2 = NULL;
          udp_header_t * udp3 = NULL;

          ip46_address_set_ip4(&src0, &((ip4_header_t *)ptr0)->src_address);
          ip46_address_set_ip4(&dst0, &((ip4_header_t *)ptr0)->dst_address);
          udp0 = (udp_header_t *)(ptr0 + sizeof(ip4_header_t));
          next0 = UDP4_DECAP_NEXT_LOOKUP_IP4;

          ip46_address_set_ip4(&src1, &((ip4_header_t *)ptr1)->src_address);
          ip46_address_set_ip4(&dst1, &((ip4_header_t *)ptr1)->dst_address);
          udp1 = (udp_header_t *)(ptr1 + sizeof(ip4_header_t));
          next1 = UDP4_DECAP_NEXT_LOOKUP_IP4;

          ip46_address_set_ip4(&src2, &((ip4_header_t *)ptr2)->src_address);
          ip46_address_set_ip4(&dst2, &((ip4_header_t *)ptr2)->dst_address);
          udp2 = (udp_header_t *)(ptr2 + sizeof(ip4_header_t));
          next2 = UDP4_DECAP_NEXT_LOOKUP_IP4;

          ip46_address_set_ip4(&src3, &((ip4_header_t *)ptr3)->src_address);
          ip46_address_set_ip4(&dst3, &((ip4_header_t *)ptr3)->dst_address);
          udp3 = (udp_header_t *)(ptr3 + sizeof(ip4_header_t));
          next3 = UDP4_DECAP_NEXT_LOOKUP_IP4;

          hicn_buffer_t *hicnb0, *hicnb1, *hicnb2, *hicnb3;
          hicnb0 = hicn_get_buffer(b0);
          hicnb1 = hicn_get_buffer(b1);
          hicnb2 = hicn_get_buffer(b2);
          hicnb3 = hicn_get_buffer(b3);


          /* Udp encap-decap tunnels have dst and src addresses and port swapped */
          vnet_buffer (b0)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst0, &src0, udp0->dst_port, udp0->src_port);
          vnet_buffer (b1)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst1, &src1, udp1->dst_port, udp1->src_port);
          vnet_buffer (b2)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst2, &src2, udp2->dst_port, udp2->src_port);
          vnet_buffer (b3)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst3, &src3, udp3->dst_port, udp3->src_port);

          if (vnet_buffer (b0)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb0->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          if (vnet_buffer (b1)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb1->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          if (vnet_buffer (b2)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb2->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          if (vnet_buffer (b3)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb3->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          udp_decap_trace_buffer (vm, node, 1, b0);
          udp_decap_trace_buffer (vm, node, 1, b1);
          udp_decap_trace_buffer (vm, node, 1, b2);
          udp_decap_trace_buffer (vm, node, 1, b3);

          vlib_buffer_advance(b0, advance);
          vlib_buffer_advance(b1, advance);
          vlib_buffer_advance(b2, advance);
          vlib_buffer_advance(b3, advance);

          vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Dual loop, X1 */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0;
          /* udp_encap_t *udp_tunnel0 = NULL; */
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

          u8 advance = sizeof(ip4_header_t) + sizeof(udp_header_t);;

          vlib_buffer_advance(b0, -advance);

          u8 *ptr0 = vlib_buffer_get_current (b0);

          ip46_address_t src0 = {0};
          ip46_address_t dst0 = {0};
          udp_header_t * udp0 = NULL;

          ip46_address_set_ip4(&src0, &((ip4_header_t *)ptr0)->src_address);
          ip46_address_set_ip4(&dst0, &((ip4_header_t *)ptr0)->dst_address);
          udp0 = (udp_header_t *)(ptr0 + sizeof(ip4_header_t));
          next0 = UDP4_DECAP_NEXT_LOOKUP_IP4;

          hicn_buffer_t *hicnb0 = hicn_get_buffer(b0);

          vnet_buffer (b0)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst0, &src0, udp0->dst_port, udp0->src_port);

          if (vnet_buffer (b0)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb0->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          udp_decap_trace_buffer (vm, node, 1, b0);

          vlib_buffer_advance(b0, advance);

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);

	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return (frame->n_vectors);
}


/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(udp4_decap_node) =
{
  .function = udp4_decap_node_fn,
  .name = "udp4-decap",
  .vector_size = sizeof(u32),
  .format_trace = format_udp_decap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(udp_decap_error_strings),
  .error_strings = udp_decap_error_strings,
  .n_next_nodes = UDP4_DECAP_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [UDP4_DECAP_NEXT_LOOKUP_IP4] = "ip4-lookup",
  },
};
/* *INDENT-ON* */

static uword
udp6_decap_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                   vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next, next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Dual loop, X2 */
      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
          vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 bi0, bi1, bi2, bi3;
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

          u8 advance = sizeof(ip6_header_t) + sizeof(udp_header_t);

          vlib_buffer_advance(b0, -advance);
          vlib_buffer_advance(b1, -advance);
          vlib_buffer_advance(b2, -advance);
          vlib_buffer_advance(b3, -advance);

          u8 *ptr0 = vlib_buffer_get_current (b0);
          u8 *ptr1 = vlib_buffer_get_current (b0);
          u8 *ptr2 = vlib_buffer_get_current (b0);
          u8 *ptr3 = vlib_buffer_get_current (b0);

          ip46_address_t src0 = {0};
          ip46_address_t src1 = {0};
          ip46_address_t src2 = {0};
          ip46_address_t src3 = {0};

          ip46_address_t dst0 = {0};
          ip46_address_t dst1 = {0};
          ip46_address_t dst2 = {0};
          ip46_address_t dst3 = {0};

          udp_header_t * udp0 = NULL;
          udp_header_t * udp1 = NULL;
          udp_header_t * udp2 = NULL;
          udp_header_t * udp3 = NULL;

          ip46_address_set_ip6(&src0, &((ip6_header_t *)ptr0)->src_address);
          ip46_address_set_ip6(&dst0, &((ip6_header_t *)ptr0)->dst_address);
          udp0 = (udp_header_t *)(ptr0 + sizeof(ip6_header_t));
          next0 = UDP6_DECAP_NEXT_LOOKUP_IP6;

          ip46_address_set_ip6(&src1, &((ip6_header_t *)ptr1)->src_address);
          ip46_address_set_ip6(&dst1, &((ip6_header_t *)ptr1)->dst_address);
          udp1 = (udp_header_t *)(ptr1 + sizeof(ip6_header_t));
          next1 = UDP6_DECAP_NEXT_LOOKUP_IP6;

          ip46_address_set_ip6(&src2, &((ip6_header_t *)ptr2)->src_address);
          ip46_address_set_ip6(&dst2, &((ip6_header_t *)ptr2)->dst_address);
          udp2 = (udp_header_t *)(ptr2 + sizeof(ip6_header_t));
          next2 = UDP6_DECAP_NEXT_LOOKUP_IP6;

          ip46_address_set_ip6(&src3, &((ip6_header_t *)ptr3)->src_address);
          ip46_address_set_ip6(&dst3, &((ip6_header_t *)ptr3)->dst_address);
          udp3 = (udp_header_t *)(ptr3 + sizeof(ip6_header_t));
          next3 = UDP6_DECAP_NEXT_LOOKUP_IP6;

          hicn_buffer_t *hicnb0, *hicnb1, *hicnb2, *hicnb3;
          hicnb0 = hicn_get_buffer(b0);
          hicnb1 = hicn_get_buffer(b1);
          hicnb2 = hicn_get_buffer(b2);
          hicnb3 = hicn_get_buffer(b3);


          /* Udp encap-decap tunnels have dst and src addresses and port swapped */
          vnet_buffer (b0)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst0, &src0, udp0->dst_port, udp0->src_port);
          vnet_buffer (b1)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst1, &src1, udp1->dst_port, udp1->src_port);
          vnet_buffer (b2)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst2, &src2, udp2->dst_port, udp2->src_port);
          vnet_buffer (b3)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst3, &src3, udp3->dst_port, udp3->src_port);

          if (vnet_buffer (b0)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb0->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          if (vnet_buffer (b1)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb1->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          if (vnet_buffer (b2)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb2->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          if (vnet_buffer (b3)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb3->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          udp_decap_trace_buffer (vm, node, 0, b0);
          udp_decap_trace_buffer (vm, node, 0, b1);
          udp_decap_trace_buffer (vm, node, 0, b2);
          udp_decap_trace_buffer (vm, node, 0, b3);

          vlib_buffer_advance(b0, advance);
          vlib_buffer_advance(b1, advance);
          vlib_buffer_advance(b2, advance);
          vlib_buffer_advance(b3, advance);

          vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}

      /* Dual loop, X1 */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 bi0;
          /* udp_encap_t *udp_tunnel0 = NULL; */
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

          u8 advance = sizeof(ip6_header_t) + sizeof(udp_header_t);

          vlib_buffer_advance(b0, -advance);

          u8 *ptr0 = vlib_buffer_get_current (b0);

          ip46_address_t src0 = {0};
          ip46_address_t dst0 = {0};
          udp_header_t * udp0 = NULL;

          ip46_address_set_ip6(&src0, &((ip6_header_t *)ptr0)->src_address);
          ip46_address_set_ip6(&dst0, &((ip6_header_t *)ptr0)->dst_address);
          udp0 = (udp_header_t *)(ptr0 + sizeof(ip6_header_t));
          next0 = UDP6_DECAP_NEXT_LOOKUP_IP6;

          hicn_buffer_t *hicnb0 = hicn_get_buffer(b0);

          vnet_buffer (b0)->ip.adj_index[VLIB_RX] = udp_tunnel_get(&dst0, &src0, udp0->dst_port, udp0->src_port);

          if (vnet_buffer (b0)->ip.adj_index[VLIB_RX] !=
              UDP_TUNNEL_INVALID)
            hicnb0->flags |= HICN_BUFFER_FLAGS_FROM_UDP_TUNNEL;

          udp_decap_trace_buffer (vm, node, 0, b0);

          vlib_buffer_advance(b0, advance);

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                           n_left_to_next, bi0, next0);

	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return (frame->n_vectors);
}


/*
 * Node registration for the interest forwarder node
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(udp6_decap_node) =
{
  .function = udp6_decap_node_fn,
  .name = "udp6-decap",
  .vector_size = sizeof(u32),
  .format_trace = format_udp_decap_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(udp_decap_error_strings),
  .error_strings = udp_decap_error_strings,
  .n_next_nodes = UDP6_DECAP_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes =
  {
    [UDP6_DECAP_NEXT_LOOKUP_IP6] = "ip6-lookup"
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
