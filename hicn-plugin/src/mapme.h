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

#ifndef __HICN_MAPME__
#define __HICN_MAPME__

#include <vnet/dpo/load_balance.h>
#include <vnet/buffer.h>
//#include <hicn/hicn.h>
#include <hicn/mapme.h>

#include "hicn.h"
#include "strategy_dpo_ctx.h"
#include "strategy_dpo_manager.h"	// dpo_is_hicn

#define HICN_MAPME_ALLOW_LOCATORS 1

//#define HICN_MAPME_NOTIFICATIONS 1

#define NOT_A_NOTIFICATION false
#define TIMER_NO_REPEAT false

#define INVALID_SEQ 0

STATIC_ASSERT (sizeof(u32) == sizeof(seq_t),
               "seq_t is not 4 bytes");

typedef struct hicn_mapme_conf_s
{
  hicn_mapme_conf_t conf;
  bool remove_dpo;		// FIXME used ?

  vlib_main_t *vm;
  vlib_log_class_t log_class;
} hicn_mapme_main_t;

#define foreach_hicn_mapme_event  \
  _(FACE_ADD)                     \
  _(FACE_DEL)                     \
  _(FACE_APP_ADD)                 \
  _(FACE_APP_DEL)                 \
  _(FACE_NH_SET)                  \
  _(FACE_NH_ADD)                  \
  _(FACE_PH_ADD)                  \
  _(FACE_PH_DEL)

typedef enum
{
#define _(a) HICN_MAPME_EVENT_##a,
  foreach_hicn_mapme_event
#undef _
} hicn_mapme_event_t;

typedef hicn_dpo_ctx_t hicn_mapme_tfib_t;

/*
 * Ideally we might need to care about alignment, but this struct is only
 * used for casting hicn_dpo_ctx_t.
 *
 * See otherwise vnet/dpo/dpo.h
 */

STATIC_ASSERT (sizeof (hicn_mapme_tfib_t) <= sizeof (hicn_dpo_ctx_t),
	       "hicn_mapme_tfib_t is greater than hicn_dpo_ctx_t");

#define TFIB(dpo) ((hicn_mapme_tfib_t*)(dpo))

static_always_inline int
hicn_mapme_nh_set (hicn_mapme_tfib_t * tfib, dpo_id_t * face_id)
{
  tfib->next_hops[0] = *face_id;
  tfib->entry_count = 1;
  return 0;
}

/**
 * @brief Add a next hop iif it is not already a next hops
 */
static_always_inline int
hicn_mapme_nh_add (hicn_mapme_tfib_t * tfib, hicn_face_id_t face_id)
{
  for (u8 pos = 0; pos < tfib->entry_count; pos++)
    if (tfib->next_hops[pos] == face_id)
      return 0;
  tfib->next_hops[tfib->entry_count++] = face_id;
  return 0;
}

/**
 * Add a 'previous' hop to the TFIB
 *
 * XXX we should have the for look in the reverse order for simpler code.
 */
static_always_inline int
hicn_mapme_tfib_add (hicn_mapme_tfib_t * tfib, dpo_id_t * face_id)
{
  u8 pos = HICN_PARAM_FIB_ENTRY_NHOPS_MAX - tfib->tfib_entry_count;

  //XXX don 't add if it already exist
  // eg.an old IU received on a face on which we are retransmitting
  for (u8 pos2 = pos; pos2 < HICN_PARAM_FIB_ENTRY_NHOPS_MAX; pos2++)
    if (dpo_cmp (&tfib->next_hops[pos2], face_id) == 0)
      return 0;

  //Make sure we have enough room
  if (pos <= tfib->entry_count)
    return -1;

  tfib->next_hops[pos - 1] = *face_id;
  tfib->tfib_entry_count++;

  return 0;
}

static_always_inline int
hicn_mapme_tfib_clear (hicn_mapme_tfib_t * tfib)
{
  dpo_id_t invalid = NEXT_HOP_INVALID;
  /*
   * We need to do a linear scan of TFIB entries to find the one to
   * remove
   */
  u8 start_pos = HICN_PARAM_FIB_ENTRY_NHOPS_MAX - tfib->tfib_entry_count;
  u8 pos = ~0;
  for (pos = start_pos; pos < HICN_PARAM_FIB_ENTRY_NHOPS_MAX; pos++)
      {
	hicn_face_unlock_with_id (&tfib->next_hops[pos]);
	tfib->next_hops[pos] = invalid;
	break;
      }

  tfib->tfib_entry_count = 0;

  return 0;
}

static_always_inline int
hicn_mapme_tfib_del (hicn_mapme_tfib_t * tfib, hicn_face_id_t face_id)
{
  hicn_face_id_t invalid = NEXT_HOP_INVALID;
  /*
   * We need to do a linear scan of TFIB entries to find the one to
   * remove
   */
  u8 start_pos = HICN_PARAM_FIB_ENTRY_NHOPS_MAX - tfib->tfib_entry_count;
  u8 pos = ~0;
  for (pos = start_pos; pos < HICN_PARAM_FIB_ENTRY_NHOPS_MAX; pos++)
    if (tfib->next_hops[pos] == face_id)
      {
	hicn_face_unlock_with_id (&tfib->next_hops[pos]);
	tfib->next_hops[pos] = invalid;
	break;
      }
  if (pos == HICN_PARAM_FIB_ENTRY_NHOPS_MAX)
    /* Not found */
    return -1;

  tfib->tfib_entry_count--;

  /* Likely we won't receive a new IU twice from the same face */
  if (PREDICT_TRUE (pos > start_pos))
    memmove (tfib->next_hops + start_pos, tfib->next_hops + start_pos + 1,
	     (pos - start_pos) * sizeof (hicn_face_id_t));

  return 0;
}

/**
 * @brief Performs an Exact Prefix Match lookup on the FIB
 * @returns the corresponding DPO (hICN or IP LB), or NULL
 */
static_always_inline
  dpo_id_t * fib_epm_lookup (ip46_address_t * addr, u8 plen)
{
  fib_prefix_t fib_pfx;
  fib_node_index_t fib_entry_index;
  u32 fib_index;
  dpo_id_t *dpo_id;
  load_balance_t *lb;

  const dpo_id_t *load_balance_dpo_id;

  /* At this point the face exists in the face table */
  fib_prefix_from_ip46_addr (addr, &fib_pfx);
  fib_pfx.fp_len = plen;

  /* Check if the route already exist in the fib : EPM */
  fib_index = fib_table_find (fib_pfx.fp_proto, HICN_FIB_TABLE);

  fib_entry_index = fib_table_lookup_exact_match (fib_index, &fib_pfx);
  if (fib_entry_index == FIB_NODE_INDEX_INVALID)
    return NULL;

  load_balance_dpo_id = fib_entry_contribute_ip_forwarding (fib_entry_index);

  /* The dpo is not a load balance dpo as expected */
  if (load_balance_dpo_id->dpoi_type != DPO_LOAD_BALANCE)
    return NULL;

  /* former_dpo_id is a load_balance dpo */
  lb = load_balance_get (load_balance_dpo_id->dpoi_index);

  /* Check if there is only one bucket */

  /*
   * We now distinguish the case where we have an hICN route (the
   * regular case), and the case where we have an IP route, to be able
   * to apply MAP-Me mechanisms even to a locator IP address.
   */

  for (int i = 0; i < lb->lb_n_buckets; i++)
    {
      /* un-const */
      dpo_id = (dpo_id_t *) load_balance_get_bucket_i (lb, i);

      if (dpo_is_hicn (dpo_id))
	return dpo_id;
    }

  /* un-const */
  return (dpo_id_t *) load_balance_dpo_id;
}

/* DPO types */

extern dpo_type_t hicn_face_udp_type;
extern dpo_type_t hicn_face_ip_type;

/* VLIB EDGE IDs */

/* in faces/ip/face_ip.c */
extern u32 strategy_face_ip4_vlib_edge;
extern u32 strategy_face_ip6_vlib_edge;
/* in faces/udp/face_udp.c */
extern u32 strategy_face_udp4_vlib_edge;
extern u32 strategy_face_udp6_vlib_edge;


/**
 * @brief Returns the next hop vlib edge on which we can send an Interest packet.
 *
 * This is both used to preprocess a dpo that will be stored as a next hop in the FIB, and to determine on which node to send an Interest Update.
 */
always_inline u32
hicn_mapme_get_dpo_vlib_edge (dpo_id_t * dpo)
{
  if (dpo->dpoi_type == hicn_face_ip_type)
    {
      switch (dpo->dpoi_proto)
	{
	case DPO_PROTO_IP4:
	  return strategy_face_ip4_vlib_edge;
	case DPO_PROTO_IP6:
	  return strategy_face_ip6_vlib_edge;
	default:
	  return ~0;
	}
    }
  else if (dpo->dpoi_type == hicn_face_udp_type)
    {
      switch (dpo->dpoi_proto)
	{
	case DPO_PROTO_IP4:
	  return strategy_face_udp4_vlib_edge;
	case DPO_PROTO_IP6:
	  return strategy_face_udp6_vlib_edge;
	default:
	  return ~0;
	}
    }
  else
    {
      return ~0;
    }
}

/**
 * @brief Returns the next hop node on which we can send an Update packet
 */
always_inline char *
hicn_mapme_get_dpo_face_node (dpo_id_t * dpo)
{
  if (dpo->dpoi_type == hicn_face_ip_type)
    {
      switch (dpo->dpoi_proto)
	{
	case DPO_PROTO_IP4:
	  return "hicn-face-ip4-output";
	case DPO_PROTO_IP6:
	  return "hicn-face-ip6-output";
	default:
	  return NULL;
	}
    }
  else if (dpo->dpoi_type == hicn_face_udp_type)
    {
      switch (dpo->dpoi_proto)
	{
	case DPO_PROTO_IP4:
	  return "hicn-face-udp4-output";
	case DPO_PROTO_IP6:
	  return "hicn-face-udp6-output";
	default:
	  return NULL;
	}
    }
  else
    {
      return NULL;
    }
}

#define DEBUG(...)		//vlib_log_debug(mapme_main.log_class, __VA_ARGS__)
#define WARN(...)		//vlib_log_warn(mapme_main.log_class, __VA_ARGS__)
#define ERROR(...)		//vlib_log_err(mapme_main.log_class, __VA_ARGS__)

#endif /* __HICN_MAPME__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
