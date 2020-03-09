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

#include "hicn.h"
#include "strategy_dpo_ctx.h"
#include "mapme.h"
#include "mapme_eventmgr.h"
#include "strategies/dpo_mw.h"

#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>

#define DEFAULT_TIMEOUT 1.0	/* s */

hicn_mapme_main_t mapme_main;

hicn_prefix_t *retx_pool;
uword *retx_hash;

void
hicn_mapme_init (vlib_main_t * vm)
{
  mapme_main.vm = vm;
  mapme_main.log_class = vlib_log_register_class ("hicn_mapme", 0);
}

/* borrowed from vnet/fib/ip4_fib.c */

typedef struct ip4_fib_show_walk_ctx_t_
{
  fib_node_index_t *ifsw_indicies;
} ip4_fib_show_walk_ctx_t;

static fib_table_walk_rc_t
ip4_fib_show_walk_cb (fib_node_index_t fib_entry_index, void *arg)
{
  ip4_fib_show_walk_ctx_t *ctx = arg;

  vec_add1 (ctx->ifsw_indicies, fib_entry_index);

  return (FIB_TABLE_WALK_CONTINUE);
}

/* borrowed from vnet/fib/ip6_fib.c */

typedef struct ip6_fib_show_ctx_t_
{
  fib_node_index_t *entries;
} ip6_fib_show_ctx_t;

static fib_table_walk_rc_t
ip6_fib_table_show_walk (fib_node_index_t fib_entry_index, void *arg)
{
  ip6_fib_show_ctx_t *ctx = arg;

  vec_add1 (ctx->entries, fib_entry_index);

  return (FIB_TABLE_WALK_CONTINUE);
}

void
hicn_mapme_process_fib_entry (vlib_main_t * vm, dpo_id_t face,
			      const fib_node_index_t * fib_entry_index)
{
  const dpo_id_t *load_balance_dpo_id;
  load_balance_t *lb;
  dpo_id_t *dpo_id;
  fib_entry_t *fib_entry;

  load_balance_dpo_id = fib_entry_contribute_ip_forwarding (*fib_entry_index);

  /* The dpo is not a load balance dpo as expected */
  if (load_balance_dpo_id->dpoi_type != DPO_LOAD_BALANCE)
    return;

  /* former_dpo_id is a load_balance dpo */
  lb = load_balance_get (load_balance_dpo_id->dpoi_index);

  for (int i = 0; i < lb->lb_n_buckets; i++)
    {
      /* un-const */
      dpo_id = (dpo_id_t *) load_balance_get_bucket_i (lb, i);

      if (dpo_is_hicn (dpo_id))
	{
	  fib_entry = fib_entry_get (*fib_entry_index);
	  vlib_cli_output (vm, "set face pending %U", format_fib_prefix,
			   &fib_entry->fe_prefix);
	}
    }
}

void
hicn_mapme_process_ip4_fib (vlib_main_t * vm, dpo_id_t face)
{
  ip4_main_t *im4 = &ip4_main;
  fib_table_t *fib_table;
  int table_id = -1, fib_index = ~0;

    /* *INDENT-OFF* */
    pool_foreach (fib_table, im4->fibs,
    ({
        ip4_fib_t *fib = pool_elt_at_index(im4->v4_fibs, fib_table->ft_index);

        if (table_id >= 0 && table_id != (int)fib->table_id)
            continue;
        if (fib_index != ~0 && fib_index != (int)fib->index)
            continue;

        fib_node_index_t *fib_entry_index;
        ip4_fib_show_walk_ctx_t ctx = {
            .ifsw_indicies = NULL,
        };

        ip4_fib_table_walk(fib, ip4_fib_show_walk_cb, &ctx);
        //vec_sort_with_function(ctx.ifsw_indicies, fib_entry_cmp_for_sort);

        vec_foreach(fib_entry_index, ctx.ifsw_indicies)
        {
            hicn_mapme_process_fib_entry(vm, face, fib_entry_index);
        }

        vec_free(ctx.ifsw_indicies);
    }));
    /* *INDENT-ON* */
}

void
hicn_mapme_process_ip6_fib (vlib_main_t * vm, dpo_id_t face)
{
  /* Walk IPv6 FIB */
  ip6_main_t *im6 = &ip6_main;
  fib_table_t *fib_table;
  ip6_fib_t *fib;
  int table_id = -1, fib_index = ~0;

    /* *INDENT-OFF* */
    pool_foreach (fib_table, im6->fibs,
    ({
        fib = pool_elt_at_index(im6->v6_fibs, fib_table->ft_index);

        if (table_id >= 0 && table_id != (int)fib->table_id)
            continue;
        if (fib_index != ~0 && fib_index != (int)fib->index)
            continue;
        if (fib_table->ft_flags & FIB_TABLE_FLAG_IP6_LL)
            continue;

        fib_node_index_t *fib_entry_index;
        ip6_fib_show_ctx_t ctx = {
            .entries = NULL,
        };

        ip6_fib_table_walk(fib->index, ip6_fib_table_show_walk, &ctx);
        //vec_sort_with_function(ctx.entries, fib_entry_cmp_for_sort);

        vec_foreach(fib_entry_index, ctx.entries)
        {
            hicn_mapme_process_fib_entry(vm, face, fib_entry_index);
        }

        vec_free(ctx.entries);

    }));
    /* *INDENT-ON* */
}


/**
 * Callback called everytime a new face is created (not including app faces)
 */
void
hicn_mapme_on_face_added (vlib_main_t * vm, dpo_id_t face)
{
  hicn_mapme_process_ip4_fib (vm, face);
  hicn_mapme_process_ip6_fib (vm, face);
}

/*
 * We need a retransmission pool holding all necessary information for crafting
 * special interests, thus including both the DPO and the prefix associated to
 * it.
 */
#define NUM_RETX_ENTRIES 100
#define NUM_RETX_SLOT 2
#define NEXT_SLOT(cur) (1-cur)
#define CUR retx_array[cur]
#define NXT retx_array[NEXT_SLOT(cur)]
#define CURLEN retx_len[cur]
#define NXTLEN retx_len[NEXT_SLOT(cur)]

static_always_inline void *
get_packet_buffer (vlib_main_t * vm, u32 node_index, u32 dpoi_index,
		   ip46_address_t * addr, hicn_type_t type)
{
  vlib_frame_t *f;
  vlib_buffer_t *b;		// for newly created packet
  u32 *to_next;
  u32 bi;
  u8 *buffer;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      clib_warning ("buffer allocation failure");
      return NULL;
    }

  /* Create a new packet from scratch */
  b = vlib_get_buffer (vm, bi);
  ASSERT (b->current_data == 0);

  /* Face information for next hop node index */
  vnet_buffer (b)->ip.adj_index[VLIB_TX] = dpoi_index;
  hicn_get_buffer (b)->type = type;

  /* Enqueue the packet right now */
  f = vlib_get_frame_to_node (vm, node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, node_index, f);

  // pointer to IP layer ? do we need to prepare for ethernet ???
  buffer = vlib_buffer_get_current (b);
  b->current_length =
    (type.l1 == IPPROTO_IPV6) ? HICN_MAPME_V6_HDRLEN : HICN_MAPME_V4_HDRLEN;

  return buffer;
}

static_always_inline bool
hicn_mapme_send_message (vlib_main_t * vm, const hicn_prefix_t * prefix,
			 mapme_params_t * params, dpo_id_t * face)
{
  size_t n;

  /* This should be retrieved from face information */
  DEBUG ("Retransmission for prefix %U seq=%d", format_ip46_address,
	 &prefix->name, IP46_TYPE_ANY, params->seq);

  char *node_name = hicn_mapme_get_dpo_face_node (face);
  if (!node_name)
    {
      clib_warning
	("Could not determine next node for sending MAP-Me packet");
      return false;
    }

  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) node_name);
  u32 node_index = node->index;

  u8 *buffer = get_packet_buffer (vm, node_index, face->dpoi_index,
				  (ip46_address_t *) prefix,
				  (params->protocol ==
				   IPPROTO_IPV6) ? HICN_TYPE_IPV6_ICMP :
				  HICN_TYPE_IPV4_ICMP);
  n = hicn_mapme_create_packet (buffer, prefix, params);
  if (n <= 0)
    {
      clib_warning ("Could not create MAP-Me packet");
      return false;
    }

  return true;
}

static_always_inline void
hicn_mapme_send_updates (vlib_main_t * vm, hicn_prefix_t * prefix,
			 dpo_id_t dpo, bool send_all)
{
  hicn_mapme_tfib_t *tfib = TFIB (hicn_strategy_dpo_ctx_get (dpo.dpoi_index));
  if (!tfib)
    {
      DEBUG ("NULL TFIB entry id=%d", dpo.dpoi_index);
      return;
    }

  u8 tfib_last_idx = HICN_PARAM_FIB_ENTRY_NHOPS_MAX - tfib->tfib_entry_count;

  mapme_params_t params = {
    .protocol = ip46_address_is_ip4 (&prefix->name)
      ? IPPROTO_IP : IPPROTO_IPV6,
    .type = UPDATE,
    .seq = tfib->seq,
  };

  if (send_all)
    {
      for (u8 pos = tfib_last_idx; pos < HICN_PARAM_FIB_ENTRY_NHOPS_MAX;
	   pos++)
	{
	  hicn_mapme_send_message (vm, prefix, &params,
				   &tfib->next_hops[pos]);
	}
    }
  else
    {
      hicn_mapme_send_message (vm, prefix, &params,
			       &tfib->next_hops[tfib_last_idx]);
    }
}

static uword
hicn_mapme_eventmgr_process (vlib_main_t * vm,
			     vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  f64 timeout = 0;		/* By default, no timer is run */
  f64 current_time, due_time;
  u8 idle = 0;

  retx_t retx_array[NUM_RETX_SLOT][NUM_RETX_ENTRIES];
  memset (retx_array, 0, NUM_RETX_SLOT * NUM_RETX_ENTRIES);
  u8 retx_len[NUM_RETX_SLOT] = { 0 };
  u8 cur = 0;			/* current slot */

  hicn_mapme_init (vm);

  for (;;)
    {
      /* NOTE: returned timeout seems to always be 0 with get_event_data
       * instead of get_event, and we thus need to reimplement timeout
       * management on top, as done elsewhere in VPP code.
       *
       * The most probable event. For simplicity, for new faces, we pass the same retx_t with no
       * prefix
       */
      if (timeout != 0)
	{
	  /* timeout = */ vlib_process_wait_for_event_or_clock (vm, timeout);
	  current_time = vlib_time_now (vm);

	  /*
	   * As we don't accummulate errors, we allow for simple timer
	   * management with no error correction accounting for elapsed time.
	   * Also, we only run a timer when there are pending retransmissions.
	   */
	  timeout =
	    (due_time >
	     current_time) ? due_time - current_time : DEFAULT_TIMEOUT;
	  due_time = current_time + timeout;
	}
      else
	{
	  vlib_process_wait_for_event (vm);
	}

      uword event_type = ~0;
      void *event_data = vlib_process_get_event_data (vm, &event_type);

      switch (event_type)
	{
	case HICN_MAPME_EVENT_FACE_ADD:
	  {
	    /*
	     * A face has been added:
	     *  - In case of a local app face, we need to advertise a new prefix
	     *  - For another local face type, we need to advertise local
	     *  prefixes and schedule retransmissions
	     */
	    retx_t *retx_events = event_data;
	    for (u8 i = 0; i < vec_len (retx_events); i++)
	      {
		hicn_mapme_on_face_added (vm, retx_events[i].dpo);
	      }
	    idle = 0;
	  }
	  break;

	case HICN_MAPME_EVENT_FACE_DEL:
	  idle = 0;
	  break;

	case HICN_MAPME_EVENT_FACE_NH_SET:
	  {
	    /*
	     * An hICN FIB entry has been modified. All operations so far
	     * have been procedded in the nodes. Here we need to track
	     * retransmissions upon timeout: we mark the FIB entry as pending in
	     * the second-to-next slot
	     */

	    /* Mark FIB entry as pending for second-to-next slot */
	    retx_t *retx_events = event_data;
	    for (u8 i = 0; i < vec_len (retx_events); i++)
	      {
		/*
		 * retx_events[i] corresponds to the dpoi_index of the (T)FIB
		 * structure that has been modified. Multiple successive
		 * events might correspond to the same entry.
		 *
		 * The FIB entry has a new next hop, and its TFIB section has:
		 *  - eventually previous prev hops for which a IU with a
		 *  lower seqno has been sent
		 *  - the prev hops that have just been added.
		 *
		 * We don't distinguish any and just send an updated IU to all
		 * of them. The retransmission of the latest IU to all
		 * facilitates the matching of ACKs to a single seqno which is
		 * the one stored in the FIB.
		 *
		 * Since we retransmit to all prev hops, we can remove this
		 * (T)FIB entry for the check at the end of the current slot.
		 */
		retx_t *retx = (retx_t *) & retx_events[i];

		retx->rtx_count = 0;
		/*
		 * Transmit IU for all TFIB entries with latest seqno (we have
		 * at least one for sure!)
		 */
		hicn_mapme_send_updates (vm, &retx->prefix, retx->dpo, true);

		/* Delete entry_id from retransmissions in the current slot (if present) ... */
		for (u8 j = 0; j < CURLEN; j++)
		  if (!dpo_cmp (&(CUR[j].dpo), &retx->dpo))
		    {
		      CUR[j].dpo.dpoi_index = ~0;	/* sufficient */
		    }

		/* ... and schedule it for next slot (if not already) */
		u8 j;
		for (j = 0; j < NXTLEN; j++)
		  if (!dpo_cmp (&NXT[j].dpo, &retx->dpo))
		    break;
		if (j == NXTLEN)	/* not found */
		  NXT[NXTLEN++] = *retx;
	      }
	    idle = 0;
	  }
	  break;

	case HICN_MAPME_EVENT_FACE_NH_ADD:
	  /*
	   * As per the description of states, this event should add the face
	   * to the list of next hops, and eventually remove it from TFIB.
	   * This corresponds to the multipath case.
	   *
	   * In all cases, we assume the propagation was already done when the first
	   * interest with the same sequence number was received, so we stop here
	   * No change in TFIB = no IU to send
	   *
	   * No change in timers.
	   */
	  vlib_cli_output (vm, "[hicn_event_mgr] ADD NEXT HOP IN FIB");

	  /* Add ingress face as next hop */
	  idle = 0;

	  break;

	case HICN_MAPME_EVENT_FACE_PH_ADD:
	  /* Back-propagation, interesting even for IN (desync) */
	  {
	    retx_t *retx_events = event_data;
	    for (u8 i = 0; i < vec_len (retx_events); i++)
	      {
		hicn_mapme_send_updates (vm, &retx_events[i].prefix,
					 retx_events[i].dpo, false);
	      }
	    idle = 0;
	  }
	  break;

	case HICN_MAPME_EVENT_FACE_PH_DEL:
	  /* Ack : remove an element from TFIB */
	  break;

	case ~0:
	  /* Timeout occurred, we have to retransmit IUs for all pending
	   * prefixes having entries in TFIB
	   *
	   * timeouts are slotted
	   *    |     |     |     |
	   *
	   *      ^
	   *      +- event occurred
	   *            new face, wait for the second next
	   *            (having two arrays and swapping cur and next)
	   *         retx : put in next
	   */
	  idle += 1;
	  for (u8 pos = 0; pos < CURLEN; pos++)
	    {
	      retx_t *retx = &CUR[pos];

	      if (retx->dpo.dpoi_index == ~0)	/* deleted entry */
		continue;

	      hicn_mapme_tfib_t *tfib =
		TFIB (hicn_strategy_dpo_ctx_get (retx->dpo.dpoi_index));
	      if (!tfib)
		{
		  DEBUG ("NULL TFIB entry for dpoi_index=%d",
			 retx->dpo.dpoi_index);
		  continue;
		}

	      hicn_mapme_send_updates (vm, &retx->prefix, retx->dpo, true);

	      retx->rtx_count++;
	      // If we exceed the numver of retransmittion it means that all tfib entries have seens at least HICN_PARAM_RTX_MAX of retransmission
	      if (retx->rtx_count < HICN_PARAM_RTX_MAX)
		{
		  /*
		   * We did some retransmissions, so let's reschedule a check in the
		   * next slot
		   */
		  NXT[NXTLEN++] = CUR[pos];
		  idle = 0;
		}
	      else
		{
		  hicn_mapme_tfib_clear (tfib);
		}
	    }

	  /* Reset events in this slot and prepare for next one */
	  CURLEN = 0;
	  cur = NEXT_SLOT (cur);

	  /* After two empty slots, we disable the timer */

	  break;
	}

      if (event_data)
	vlib_process_put_event_data (vm, event_data);

      timeout = (idle > 1) ? 0 : DEFAULT_TIMEOUT;

      // if (vlib_process_suspend_time_is_zero (timeout)) { ... }

    }

  /* NOTREACHED */
  return 0;
}

/* Not static as we need to access it from hicn_face */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hicn_mapme_eventmgr_process_node) = { //,static) = {
    .function = hicn_mapme_eventmgr_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "mapme-eventmgr-process",
    .process_log2_n_stack_bytes = 16,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
