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

#ifndef __HICN_MGMT_H__
#define __HICN_MGMT_H__

#include <vppinfra/error.h>
#include "faces/face.h"
#include "hicn_api.h"

typedef struct icn_stats_s
{
  u32 pkts_processed;
  u32 pkts_interest_count;
  u32 pkts_data_count;
  u32 pkts_from_cache_count;
  u32 pkts_no_pit_count;
  u32 pit_expired_count;
  u32 cs_expired_count;
  u32 no_bufs_count;
  u32 pkts_interest_agg;
  u32 pkts_int_retrans;
  u32 pit_int_count;
  u32 pit_cs_count;
} icn_stats_t;

typedef enum
{
  HICN_MGMT_FACE_OP_NONE = 0,
  HICN_MGMT_FACE_OP_CREATE,
  HICN_MGMT_FACE_OP_DELETE,
  HICN_MGMT_FACE_OP_ADMIN,
  HICN_MGMT_FACE_OP_HELLO,
} hicn_mgmt_face_op_e;

typedef enum
{
  HICN_MGMT_MAPME_OP_NONE = 0,
  HICN_MGMT_MAPME_OP_CREATE,
  HICN_MGMT_MAPME_OP_DELETE,
  HICN_MGMT_MAPME_OP_ENABLE,
  HICN_MGMT_MAPME_OP_DISABLE
} hicn_mgmt_mapme_op_e;

typedef enum
{
  HICN_ADDRESS_TYPE_NONE,
  HICN_ADDRESS_TYPE_V4,
  HICN_ADDRESS_TYPE_V6
} hicn_address_type_e;

/*
 * Utility to update error counters in all hICN nodes
 */
always_inline void
update_node_counter (vlib_main_t * vm, u32 node_idx, u32 counter_idx, u64 val)
{
  vlib_node_t *node = vlib_get_node (vm, node_idx);
  vlib_error_main_t *em = &(vm->error_main);
  u32 base_idx = node->error_heap_index;

  em->counters[base_idx + counter_idx] = val;
}


/*
 * Stats for the forwarding node, which end up called "error" even though
 * they aren't...
 */
#define foreach_hicnfwd_error					\
  _(PROCESSED, "hICN packets processed")			\
  _(INTERESTS, "hICN interests forwarded")			\
  _(DATAS, "hICN data msgs forwarded")				\
  _(CACHED, "Cached data ")					\
  _(NO_PIT, "hICN no PIT entry drops")				\
  _(PIT_EXPIRED, "hICN expired PIT entries")			\
  _(CS_EXPIRED, "hICN expired CS entries")			\
  _(CS_LRU, "hICN LRU CS entries freed")			\
  _(NO_BUFS, "No packet buffers")				\
  _(INTEREST_AGG, "Interests aggregated")			\
  _(INTEREST_AGG_ENTRY, "Interest aggregated per entry")	\
  _(INT_RETRANS, "Interest retransmissions")			\
  _(INT_COUNT, "Interests in PIT")				\
  _(CS_COUNT, "CS total entries")				\
  _(CS_NTW_COUNT, "CS ntw entries")				\
  _(CS_APP_COUNT, "CS app entries")				\
  _(HASH_COLL_HASHTB_COUNT, "Collisions in Hash table")

typedef enum
{
#define _(sym, str) HICNFWD_ERROR_##sym,
  foreach_hicnfwd_error
#undef _
    HICNFWD_N_ERROR,
} hicnfwd_error_t;

/*
 * Declarations
 */
clib_error_t *hicn_api_plugin_hookup (vlib_main_t * vm);

int hicn_mgmt_node_stats_get (vl_api_hicn_api_node_stats_get_reply_t * rmp);

#endif /* // __HICN_MGMT_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
