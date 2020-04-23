/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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

#ifndef __HICN_ROUTE__
#define __HICN_ROUTE__

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include "hicn.h"
#include "faces/face.h"

extern fib_source_t hicn_fib_src;

extern dpo_type_t udp_encap_dpo_types[FIB_PROTOCOL_MAX];

/*
 * Retrieve the hicn dpo corresponding to a hicn prefix
 */
int
hicn_route_get_dpo (const fib_prefix_t * prefix,
		    const dpo_id_t ** hicn_dpo, u32 * fib_index);


/* Remove a next hop route for a name prefix */
int
hicn_route_set_strategy (fib_prefix_t * prefix, u32 strategy_id);

/**
 * @Brief Helper to add a nex hop in the vrf 0. If there are no entries in the
 * vrf 0 that matches with the prefix (epm), a new one is created.
 *
 * @param fib_proto FIB_PROTOCOL_IP6 or FIB_PROTOCOL_IP4 (mpls not supported)
 * @param pfx Prefix for which to add a next hop
 * @param nh Next hop to add
 * @param sw_if Software interface index to add in the next hop
 */
int
ip_nh_add_helper (fib_protocol_t fib_proto, const fib_prefix_t * pfx, ip46_address_t * nh, u32 sw_if);

/**
 * @Brief Helper to remove a nex hop in the vrf 0. If there are no entries in the
 * vrf 0 nothing happens.
 *
 * @param fib_proto FIB_PROTOCOL_IP6 or FIB_PROTOCOL_IP4 (mpls not supported)
 * @param pfx Prefix for which to remove a next hop
 * @param nh Next hop to remove
 * @param sw_if Software interface index in the next hop definition
 */
int
ip_nh_del_helper (fib_protocol_t fib_proto, const fib_prefix_t * rpfx, ip46_address_t * nh, u32 sw_if);

int
hicn_route_enable (fib_prefix_t *prefix);

int
hicn_route_disable (fib_prefix_t *prefix);


/* Init route internal strustures */
void
hicn_route_init();
#endif /* //__HICN_ROUTE__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
