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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/fib_table.h>	/* for FIB table and entry creation */
#include <vnet/fib/fib_entry.h>	/* for FIB table and entry creation */
#include <vnet/fib/ip4_fib.h>
#include <vnet/dpo/load_balance.h>

#include "mgmt.h"
#include "strategy_dpo_manager.h"

static __clib_unused char *hicn_data_input_error_strings[] = {
#define _(sym, string) string,
  foreach_hicnfwd_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} hicn_data_input_t;

typedef enum
{
  HICN_DATA_INPUT_IP6_NEXT_FACE,
  HICN_DATA_INPUT_IP6_NEXT_IP6_LOCAL,
  HICN_DATA_INPUT_IP6_N_NEXT,
} hicn_data_input_ip6_next_t;

typedef enum
{
  HICN_DATA_INPUT_IP4_NEXT_FACE,
  HICN_DATA_INPUT_IP4_NEXT_IP4_LOCAL,
  HICN_DATA_INPUT_IP4_N_NEXT,
} hicn_data_input_ip4_next_t;

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u8 isv6;
} hicn_data_input_trace_t;

vlib_node_registration_t hicn_data_input_ip6_node;
vlib_node_registration_t hicn_data_input_ip4_node;

static __clib_unused u8 *
format_hicn_data_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hicn_data_input_trace_t *t = va_arg (*args, hicn_data_input_trace_t *);
  u32 indent = format_get_indent (s);
  u8 isv6 = (u8) va_arg (*args, int);

  s =
    format (s, "%U hicn_data_input%s: sw_if_index %d next-index %d",
	    format_white_space, indent, isv6 ? "_ip6" : "_ip4",
	    t->sw_if_index, t->next_index);
  return s;
}

static uword
hicn_data_input_ip6_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip6_main_t *im = &ip6_main;
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_to_counters;
  u32 n_left_from, n_left_to_next, *from, *to_next;
  ip_lookup_next_t next;
  u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t *p0, *p1;
	  u32 pi0, pi1, lbi0, lbi1, wrong_next;
	  ip_lookup_next_t next0, next1;
	  ip6_header_t *ip0, *ip1;
	  ip6_address_t *src_addr0, *src_addr1;
	  const dpo_id_t *dpo0, *dpo1;
	  const load_balance_t *lb0, *lb1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip0[0]), LOAD);
	  }

	  pi0 = to_next[0] = from[0];
	  pi1 = to_next[1] = from[1];

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  src_addr0 = &ip0->src_address;
	  src_addr1 = &ip1->src_address;

	  ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, p0);
	  ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, p1);

	  lbi0 = ip6_fib_table_fwding_lookup (vnet_buffer (p0)->ip.fib_index,
					      src_addr0);
	  lbi1 = ip6_fib_table_fwding_lookup (vnet_buffer (p1)->ip.fib_index,
					      src_addr1);

	  lb0 = load_balance_get (lbi0);
	  lb1 = load_balance_get (lbi1);
	  ASSERT (lb0->lb_n_buckets > 0);
	  ASSERT (lb1->lb_n_buckets > 0);
	  ASSERT (is_pow2 (lb0->lb_n_buckets));
	  ASSERT (is_pow2 (lb1->lb_n_buckets));

	  vnet_buffer (p0)->ip.flow_hash = vnet_buffer (p1)->ip.flow_hash = 0;

	  //No vpp loadbalancing. Missing header file to exploit it
	  dpo0 = load_balance_get_bucket_i (lb0, 0);
	  dpo1 = load_balance_get_bucket_i (lb1, 0);

	  if (dpo_is_hicn (dpo0))
	    next0 = HICN_DATA_INPUT_IP6_NEXT_FACE;
	  else
	    next0 = HICN_DATA_INPUT_IP6_NEXT_IP6_LOCAL;

	  if (dpo_is_hicn (dpo1))
	    next1 = HICN_DATA_INPUT_IP6_NEXT_FACE;
	  else
	    next1 = HICN_DATA_INPUT_IP6_NEXT_IP6_LOCAL;

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      hicn_data_input_trace_t *t =
		vlib_add_trace (vm, node, p0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      t->isv6 = 1;
	    }

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      (p1->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      hicn_data_input_trace_t *t =
		vlib_add_trace (vm, node, p1, sizeof (*t));
	      t->sw_if_index = vnet_buffer (p1)->sw_if_index[VLIB_RX];
	      t->next_index = next1;
	      t->isv6 = 1;
	    }


	  vlib_increment_combined_counter
	    (cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, p0));
	  vlib_increment_combined_counter
	    (cm, thread_index, lbi1, 1, vlib_buffer_length_in_chain (vm, p1));

	  from += 2;
	  to_next += 2;
	  n_left_to_next -= 2;
	  n_left_from -= 2;

	  wrong_next = (next0 != next) + 2 * (next1 != next);
	  if (PREDICT_FALSE (wrong_next != 0))
	    {
	      switch (wrong_next)
		{
		case 1:
		  /* A B A */
		  to_next[-2] = pi1;
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node, next0, pi0);
		  break;

		case 2:
		  /* A A B */
		  to_next -= 1;
		  n_left_to_next += 1;
		  vlib_set_next_frame_buffer (vm, node, next1, pi1);
		  break;

		case 3:
		  /* A B C */
		  to_next -= 2;
		  n_left_to_next += 2;
		  vlib_set_next_frame_buffer (vm, node, next0, pi0);
		  vlib_set_next_frame_buffer (vm, node, next1, pi1);
		  if (next0 == next1)
		    {
		      /* A B B */
		      vlib_put_next_frame (vm, node, next, n_left_to_next);
		      next = next1;
		      vlib_get_next_frame (vm, node, next, to_next,
					   n_left_to_next);
		    }
		}
	    }
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *p0;
	  ip6_header_t *ip0;
	  u32 pi0, lbi0;
	  ip_lookup_next_t next0;
	  load_balance_t *lb0;
	  ip6_address_t *src_addr0;
	  const dpo_id_t *dpo0;

	  pi0 = from[0];
	  to_next[0] = pi0;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);
	  src_addr0 = &ip0->src_address;
	  ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, p0);
	  lbi0 = ip6_fib_table_fwding_lookup (vnet_buffer (p0)->ip.fib_index,
					      src_addr0);

	  lb0 = load_balance_get (lbi0);
	  ASSERT (lb0->lb_n_buckets > 0);
	  ASSERT (is_pow2 (lb0->lb_n_buckets));

	  //No vpp loadbalancing. Missing header file to exploit it
	  dpo0 = load_balance_get_bucket_i (lb0, 0);

	  if (dpo_is_hicn (dpo0))
	    next0 = HICN_DATA_INPUT_IP6_NEXT_FACE;
	  else
	    next0 = HICN_DATA_INPUT_IP6_NEXT_IP6_LOCAL;

	  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	      (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      hicn_data_input_trace_t *t =
		vlib_add_trace (vm, node, p0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	      t->isv6 = 1;
	    }

	  vlib_increment_combined_counter
	    (cm, thread_index, lbi0, 1, vlib_buffer_length_in_chain (vm, p0));

	  from += 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  n_left_from -= 1;

	  if (PREDICT_FALSE (next0 != next))
	    {
	      n_left_to_next += 1;
	      vlib_put_next_frame (vm, node, next, n_left_to_next);
	      next = next0;
	      vlib_get_next_frame (vm, node, next, to_next, n_left_to_next);
	      to_next[0] = pi0;
	      to_next += 1;
	      n_left_to_next -= 1;
	    }
	}

      vlib_put_next_frame (vm, node, next, n_left_to_next);
    }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn_data_input_ip6) =
    {
     .function = hicn_data_input_ip6_fn,
     .name = "hicn-data-input-ip6",
     .vector_size = sizeof(u32),
     .format_trace = format_hicn_data_input_trace,
     .type = VLIB_NODE_TYPE_INTERNAL,
     .n_errors = ARRAY_LEN(hicn_data_input_error_strings),
     .error_strings = hicn_data_input_error_strings,
     .n_next_nodes = HICN_DATA_INPUT_IP6_N_NEXT,
     .next_nodes =
     {
      [HICN_DATA_INPUT_IP6_NEXT_FACE] = "hicn-face-ip6-input",
      [HICN_DATA_INPUT_IP6_NEXT_IP6_LOCAL] = "ip6-local-end-of-arc"
     },
    };
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT(hicn_data_input_ip6_arc, static)=
    {
     .arc_name = "ip6-local",
     .node_name = "hicn-data-input-ip6",
     .runs_before = VNET_FEATURES("ip6-local-end-of-arc"),
    };
/* *INDENT-ON* */



always_inline uword
hicn_data_input_ip4_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ip4_main_t *im = &ip4_main;
  vlib_combined_counter_main_t *cm = &load_balance_main.lbm_to_counters;
  u32 n_left, *from;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  vlib_buffer_t **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);

#if (CLIB_N_PREFETCHES >= 8)
  while (n_left >= 4)
    {
      ip4_header_t *ip0, *ip1, *ip2, *ip3;
      const load_balance_t *lb0, *lb1, *lb2, *lb3;
      ip4_fib_mtrie_t *mtrie0, *mtrie1, *mtrie2, *mtrie3;
      ip4_fib_mtrie_leaf_t leaf0, leaf1, leaf2, leaf3;
      ip4_address_t *src_addr0, *src_addr1, *src_addr2, *src_addr3;
      u32 lb_index0, lb_index1, lb_index2, lb_index3;
      const dpo_id_t *dpo0, *dpo1, *dpo2, *dpo3;

      /* Prefetch next iteration. */
      if (n_left >= 8)
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);

	  CLIB_PREFETCH (b[4]->data, sizeof (ip0[0]), LOAD);
	  CLIB_PREFETCH (b[5]->data, sizeof (ip0[0]), LOAD);
	  CLIB_PREFETCH (b[6]->data, sizeof (ip0[0]), LOAD);
	  CLIB_PREFETCH (b[7]->data, sizeof (ip0[0]), LOAD);
	}

      ip0 = vlib_buffer_get_current (b[0]);
      ip1 = vlib_buffer_get_current (b[1]);
      ip2 = vlib_buffer_get_current (b[2]);
      ip3 = vlib_buffer_get_current (b[3]);

      src_addr0 = &ip0->src_address;
      src_addr1 = &ip1->src_address;
      src_addr2 = &ip2->src_address;
      src_addr3 = &ip3->src_address;

      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[0]);
      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[1]);
      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[2]);
      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[3]);

      mtrie0 = &ip4_fib_get (vnet_buffer (b[0])->ip.fib_index)->mtrie;
      mtrie1 = &ip4_fib_get (vnet_buffer (b[1])->ip.fib_index)->mtrie;
      mtrie2 = &ip4_fib_get (vnet_buffer (b[2])->ip.fib_index)->mtrie;
      mtrie3 = &ip4_fib_get (vnet_buffer (b[3])->ip.fib_index)->mtrie;

      leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, src_addr0);
      leaf1 = ip4_fib_mtrie_lookup_step_one (mtrie1, src_addr1);
      leaf2 = ip4_fib_mtrie_lookup_step_one (mtrie2, src_addr2);
      leaf3 = ip4_fib_mtrie_lookup_step_one (mtrie3, src_addr3);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, src_addr0, 2);
      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, src_addr1, 2);
      leaf2 = ip4_fib_mtrie_lookup_step (mtrie2, leaf2, src_addr2, 2);
      leaf3 = ip4_fib_mtrie_lookup_step (mtrie3, leaf3, src_addr3, 2);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, src_addr0, 3);
      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, src_addr1, 3);
      leaf2 = ip4_fib_mtrie_lookup_step (mtrie2, leaf2, src_addr2, 3);
      leaf3 = ip4_fib_mtrie_lookup_step (mtrie3, leaf3, src_addr3, 3);

      lb_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
      lb_index1 = ip4_fib_mtrie_leaf_get_adj_index (leaf1);
      lb_index2 = ip4_fib_mtrie_leaf_get_adj_index (leaf2);
      lb_index3 = ip4_fib_mtrie_leaf_get_adj_index (leaf3);

      ASSERT (lb_index0 && lb_index1 && lb_index2 && lb_index3);
      lb0 = load_balance_get (lb_index0);
      lb1 = load_balance_get (lb_index1);
      lb2 = load_balance_get (lb_index2);
      lb3 = load_balance_get (lb_index3);

      ASSERT (lb0->lb_n_buckets > 0);
      ASSERT (is_pow2 (lb0->lb_n_buckets));
      ASSERT (lb1->lb_n_buckets > 0);
      ASSERT (is_pow2 (lb1->lb_n_buckets));
      ASSERT (lb2->lb_n_buckets > 0);
      ASSERT (is_pow2 (lb2->lb_n_buckets));
      ASSERT (lb3->lb_n_buckets > 0);
      ASSERT (is_pow2 (lb3->lb_n_buckets));

      dpo0 = load_balance_get_bucket_i (lb0, 0);
      dpo1 = load_balance_get_bucket_i (lb1, 0);
      dpo2 = load_balance_get_bucket_i (lb2, 0);
      dpo3 = load_balance_get_bucket_i (lb3, 0);

      if (dpo_is_hicn (dpo0))
	next[0] = HICN_DATA_INPUT_IP4_NEXT_FACE;
      else
	next[0] = HICN_DATA_INPUT_IP4_NEXT_IP4_LOCAL;

      if (dpo_is_hicn (dpo1))
	next[1] = HICN_DATA_INPUT_IP4_NEXT_FACE;
      else
	next[1] = HICN_DATA_INPUT_IP4_NEXT_IP4_LOCAL;

      if (dpo_is_hicn (dpo2))
	next[2] = HICN_DATA_INPUT_IP4_NEXT_FACE;
      else
	next[2] = HICN_DATA_INPUT_IP4_NEXT_IP4_LOCAL;

      if (dpo_is_hicn (dpo3))
	next[3] = HICN_DATA_INPUT_IP4_NEXT_FACE;
      else
	next[3] = HICN_DATA_INPUT_IP4_NEXT_IP4_LOCAL;


      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	  (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  hicn_data_input_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  t->next_index = next[0];
	  t->isv6 = 0;
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	  (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  hicn_data_input_trace_t *t =
	    vlib_add_trace (vm, node, b[1], sizeof (*t));
	  t->sw_if_index = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
	  t->next_index = next[1];
	  t->isv6 = 0;
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	  (b[2]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  hicn_data_input_trace_t *t =
	    vlib_add_trace (vm, node, b[2], sizeof (*t));
	  t->sw_if_index = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
	  t->next_index = next[0];
	  t->isv6 = 0;
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	  (b[3]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  hicn_data_input_trace_t *t =
	    vlib_add_trace (vm, node, b[3], sizeof (*t));
	  t->sw_if_index = vnet_buffer (b[3])->sw_if_index[VLIB_RX];
	  t->next_index = next[3];
	  t->isv6 = 0;
	}

      vlib_increment_combined_counter
	(cm, thread_index, lb_index0, 1,
	 vlib_buffer_length_in_chain (vm, b[0]));
      vlib_increment_combined_counter
	(cm, thread_index, lb_index1, 1,
	 vlib_buffer_length_in_chain (vm, b[1]));
      vlib_increment_combined_counter
	(cm, thread_index, lb_index2, 1,
	 vlib_buffer_length_in_chain (vm, b[2]));
      vlib_increment_combined_counter
	(cm, thread_index, lb_index3, 1,
	 vlib_buffer_length_in_chain (vm, b[3]));

      b += 4;
      next += 4;
      n_left -= 4;
    }
#elif (CLIB_N_PREFETCHES >= 4)
  while (n_left >= 4)
    {
      ip4_header_t *ip0, *ip1;
      const load_balance_t *lb0, *lb1;
      ip4_fib_mtrie_t *mtrie0, *mtrie1;
      ip4_fib_mtrie_leaf_t leaf0, leaf1;
      ip4_address_t *src_addr0, *src_addr1;
      u32 lb_index0, lb_index1;
      flow_hash_config_t flow_hash_config0, flow_hash_config1;
      u32 hash_c0, hash_c1;
      const dpo_id_t *dpo0, *dpo1;

      /* Prefetch next iteration. */
      {
	vlib_prefetch_buffer_header (b[2], LOAD);
	vlib_prefetch_buffer_header (b[3], LOAD);

	CLIB_PREFETCH (b[2]->data, sizeof (ip0[0]), LOAD);
	CLIB_PREFETCH (b[3]->data, sizeof (ip0[0]), LOAD);
      }

      ip0 = vlib_buffer_get_current (b[0]);
      ip1 = vlib_buffer_get_current (b[1]);

      src_addr0 = &ip0->src_address;
      src_addr1 = &ip1->src_address;

      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[0]);
      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[1]);

      mtrie0 = &ip4_fib_get (vnet_buffer (b[0])->ip.fib_index)->mtrie;
      mtrie1 = &ip4_fib_get (vnet_buffer (b[1])->ip.fib_index)->mtrie;

      leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, src_addr0);
      leaf1 = ip4_fib_mtrie_lookup_step_one (mtrie1, src_addr1);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, src_addr0, 2);
      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, src_addr1, 2);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, src_addr0, 3);
      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1, src_addr1, 3);

      lb_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
      lb_index1 = ip4_fib_mtrie_leaf_get_adj_index (leaf1);

      ASSERT (lb_index0 && lb_index1);
      lb0 = load_balance_get (lb_index0);
      lb1 = load_balance_get (lb_index1);

      ASSERT (lb0->lb_n_buckets > 0);
      ASSERT (is_pow2 (lb0->lb_n_buckets));
      ASSERT (lb1->lb_n_buckets > 0);
      ASSERT (is_pow2 (lb1->lb_n_buckets));

      dpo0 = load_balance_get_bucket_i (lb0, 0);
      dpo1 = load_balance_get_bucket_i (lb1, 0);

      if (dpo_is_hicn (dpo0))
	next[0] = HICN_DATA_INPUT_IP4_NEXT_FACE;
      else
	next[0] = HICN_DATA_INPUT_IP4_NEXT_IP4_LOCAL;

      if (dpo_is_hicn (dpo1))
	next[1] = HICN_DATA_INPUT_IP4_NEXT_FACE;
      else
	next[1] = HICN_DATA_INPUT_IP4_NEXT_IP4_LOCAL;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	  (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  hicn_data_input_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  t->next_index = next[0];
	  t->isv6 = 0;
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	  (b1->flags & VLIB_BUFFER_IS_TRACED))
	{
	  hicn_data_input_trace_t *t =
	    vlib_add_trace (vm, node, b1, sizeof (*t));
	  t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  t->next_index = next[1];
	  t->isv6 = 0;
	}


      vlib_increment_combined_counter
	(cm, thread_index, lb_index0, 1,
	 vlib_buffer_length_in_chain (vm, b[0]));
      vlib_increment_combined_counter
	(cm, thread_index, lb_index1, 1,
	 vlib_buffer_length_in_chain (vm, b[1]));

      b += 2;
      next += 2;
      n_left -= 2;
    }
#endif
  while (n_left > 0)
    {
      ip4_header_t *ip0;
      const load_balance_t *lb0;
      ip4_fib_mtrie_t *mtrie0;
      ip4_fib_mtrie_leaf_t leaf0;
      ip4_address_t *src_addr0;
      u32 lbi0;
      const dpo_id_t *dpo0;

      ip0 = vlib_buffer_get_current (b[0]);
      src_addr0 = &ip0->src_address;
      ip_lookup_set_buffer_fib_index (im->fib_index_by_sw_if_index, b[0]);

      mtrie0 = &ip4_fib_get (vnet_buffer (b[0])->ip.fib_index)->mtrie;
      leaf0 = ip4_fib_mtrie_lookup_step_one (mtrie0, src_addr0);
      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, src_addr0, 2);
      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0, src_addr0, 3);
      lbi0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);

      ASSERT (lbi0);
      lb0 = load_balance_get (lbi0);

      ASSERT (lb0->lb_n_buckets > 0);
      ASSERT (is_pow2 (lb0->lb_n_buckets));

      dpo0 = load_balance_get_bucket_i (lb0, 0);

      if (dpo_is_hicn (dpo0))
	next[0] = HICN_DATA_INPUT_IP4_NEXT_FACE;
      else
	next[0] = HICN_DATA_INPUT_IP4_NEXT_IP4_LOCAL;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE) &&
	  (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  hicn_data_input_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  t->next_index = next[0];
	  t->isv6 = 0;
	}

      vlib_increment_combined_counter (cm, thread_index, lbi0, 1,
				       vlib_buffer_length_in_chain (vm,
								    b[0]));

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    ip4_forward_next_trace (vm, node, frame, VLIB_TX);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hicn_data_input_ip4) =
    {
     .function = hicn_data_input_ip4_fn,
     .name = "hicn-data-input-ip4",
     .vector_size = sizeof(u32),
     .format_trace = format_hicn_data_input_trace,
     .type = VLIB_NODE_TYPE_INTERNAL,
     .n_errors = ARRAY_LEN(hicn_data_input_error_strings),
     .error_strings = hicn_data_input_error_strings,
     .n_next_nodes = HICN_DATA_INPUT_IP4_N_NEXT,
     .next_nodes =
     {
      [HICN_DATA_INPUT_IP4_NEXT_FACE] = "hicn-face-ip4-input",
      [HICN_DATA_INPUT_IP4_NEXT_IP4_LOCAL] = "ip4-local-end-of-arc"
     },
    };
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_FEATURE_INIT(hicn_data_input_ip4_arc, static)=
    {
     .arc_name = "ip4-local",
     .node_name = "hicn-data-input-ip4",
     .runs_before = VNET_FEATURES("ip4-local-end-of-arc"),
    };
/* *INDENT-ON* */
