/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
#include <vppinfra/error.h>

#include "hicn.h"
#include "infra.h"
#include "mgmt.h"

/* define message IDs */
#include <vpp_plugins/hicn/hicn_msg_enum.h>

/* shared routine betweeen API and CLI, leveraging API message structure */
int
hicn_mgmt_node_stats_get (vl_api_hicn_api_node_stats_get_reply_t *rmp)
{
  rmp->pkts_processed = 0;
  rmp->pkts_interest_count = 0;
  rmp->pkts_data_count = 0;
  rmp->pkts_from_cache_count = 0;
  rmp->pkts_no_pit_count = 0;
  rmp->pit_expired_count = 0;
  rmp->cs_expired_count = 0;
  rmp->cs_lru_count = 0;
  rmp->pkts_drop_no_buf = 0;
  rmp->interests_aggregated = 0;
  rmp->interests_retx = 0;
  rmp->pit_entries_count =
    clib_host_to_net_u64 (hicn_main.pitcs.pcs_pit_count);
  rmp->cs_entries_count = clib_host_to_net_u64 (hicn_main.pitcs.pcs_cs_count);
  rmp->cs_entries_ntw_count =
    clib_host_to_net_u64 (hicn_main.pitcs.policy_state.count);

  vlib_error_main_t *em;
  vlib_node_t *n;
  foreach_vlib_main ()
  {
    em = &this_vlib_main->error_main;
    n = vlib_get_node (this_vlib_main, hicn_interest_pcslookup_node.index);
    u32 node_cntr_base_idx = n->error_heap_index;
    rmp->pkts_processed += clib_host_to_net_u64 (
      em->counters[node_cntr_base_idx + HICNFWD_ERROR_PROCESSED]);
    rmp->pkts_interest_count += clib_host_to_net_u64 (
      em->counters[node_cntr_base_idx + HICNFWD_ERROR_INTERESTS]);
    n = vlib_get_node (this_vlib_main, hicn_data_pcslookup_node.index);
    node_cntr_base_idx = n->error_heap_index;
    rmp->pkts_processed += clib_host_to_net_u64 (
      em->counters[node_cntr_base_idx + HICNFWD_ERROR_PROCESSED]);
    rmp->pkts_data_count += clib_host_to_net_u64 (
      em->counters[node_cntr_base_idx + HICNFWD_ERROR_DATAS]);
    n = vlib_get_node (this_vlib_main, hicn_interest_hitcs_node.index);
    node_cntr_base_idx = n->error_heap_index;
    rmp->pkts_from_cache_count += clib_host_to_net_u64 (
      em->counters[node_cntr_base_idx + HICNFWD_ERROR_CACHED]);
    n = vlib_get_node (this_vlib_main, hicn_interest_hitpit_node.index);
    node_cntr_base_idx = n->error_heap_index;
    rmp->interests_aggregated += clib_host_to_net_u64 (
      em->counters[node_cntr_base_idx + HICNFWD_ERROR_INTEREST_AGG]);
    rmp->interests_retx += clib_host_to_net_u64 (
      em->counters[node_cntr_base_idx + HICNFWD_ERROR_INT_RETRANS]);
  }
  return (HICN_ERROR_NONE);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
