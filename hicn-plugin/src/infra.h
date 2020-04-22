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

#ifndef __HICN_INFRA_H__
#define __HICN_INFRA_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "pcs.h"

/**
 * hICN plugin global state: see also
 * - fib and pits
 */
typedef struct hicn_main_s
{
  /* Binary API message ID base */
  u16 msg_id_base;

  /* Have we been enabled */
  u16 is_enabled;

  /* Forwarder PIT/CS */
  hicn_pit_cs_t pitcs;

  /* Global PIT lifetime info */
  /*
   * Boundaries for the interest lifetime. If greater than
   * pit_lifetime_max_ms, pit_lifetime_max_ms is used in the PIT
   */
  u64 pit_lifetime_max_ms;

} hicn_main_t;

extern hicn_main_t hicn_main;

extern int hicn_infra_fwdr_initialized;

/* PIT and CS size */
u32 hicn_infra_pit_size;
u32 hicn_infra_cs_size;

/**
 * @brief Enable and disable the hicn plugin
 *
 * Enable the time the hICN plugin and set the forwarder parameters.
 * @param enable_disable 1 if to enable, 0 otherwisw (currently only enable is supported)
 * @param pit_max_size Max size of the PIT
 * @param pit_max_lifetime_sec_req Maximum timeout allowed for a PIT entry lifetime
 * @param cs_max_size CS size. Must be <= than pit_max_size
 * @param cs_reserved_app Amount of CS reserved for application faces
 */
int
hicn_infra_plugin_enable_disable (int enable_disable,
				  int pit_max_size,
				  f64 pit_max_lifetime_sec_req,
				  int cs_max_size);


/* vlib nodes that compose the hICN forwarder */
extern vlib_node_registration_t hicn_interest_pcslookup_node;
extern vlib_node_registration_t hicn_data_pcslookup_node;
extern vlib_node_registration_t hicn_data_fwd_node;
extern vlib_node_registration_t hicn_data_store_node;
extern vlib_node_registration_t hicn_interest_hitpit_node;
extern vlib_node_registration_t hicn_interest_hitcs_node;
extern vlib_node_registration_t hicn_pg_interest_node;
extern vlib_node_registration_t hicn_pg_data_node;
extern vlib_node_registration_t hicn_pg_server_node;
extern vlib_node_registration_t hicn_data_input_ip6_node;
extern vlib_node_registration_t hicn_data_input_ip4_node;



#endif /* // __HICN_INFRA_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
