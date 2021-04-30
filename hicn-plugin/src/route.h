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

/**
 * @file route.h
 *
 * hICN uses a specific vrf to install the routes for a prefix has been enabled to
 * be hicn. It considers the vrf 0 (the default vrf) as the dominating vrf on
 * which every route is stored. Enabling a prefix to be hICN will copy all the routes
 * in the vrf 0 for the given prefi, in the vrf HICN. Every modification made on the
 * vrf 0 on an hICN enabled prefix is reflected in the vrf hICN (through the use of
 * the fib entry tracking functionality). Moreover, we use the lookup in the vrf hICN
 * as a way for punting packet that must be processed as hICN. The implementation will
 * install a special dpo as a single next hop for the vpp load balancer for each entry
 * in the vrf hICN that we enabled. Such dpo will have two purposes: 1) to punt packets
 * to the hICN forwarding pipeline, 2) to point to the righe strategy (the dpoi_index will
 * be an index to the strategy context while the dpoi_type will be an index to the strategy vft).
 *
 * Additionally, hICN assign each interface to the vrf hICN; this is required for
 * the interest lookup. Vpp performs a lookup in the vrf assigned to the interface,
 * therefore if an interface is not assigned to the hICN vrf, the lookup will be done
 * on the vrf 0 and the packet won't be processed through the hicn forwarding pipeline.
 */

/*
 * Adding each interface to the vrf hICN has the side effect that to ping you need to
 * specify the vrf hICN in the command.
 */

extern fib_source_t hicn_fib_src;

extern dpo_type_t udp_encap_dpo_types[FIB_PROTOCOL_MAX];

/**
 * @Brief Return the hicn_dpo corresponding to the prefix in teh vrf HICN
 *
 * @param prefix Prefix for which we want to retrieve the hICN dpo
 * @param hicn_dpo return value with the hicn_dpo
 * @param fib_index return value with the fib index corresponding to the prefix
 */
int
hicn_route_get_dpo (const fib_prefix_t * prefix,
		    const dpo_id_t ** hicn_dpo, u32 * fib_index);


/**
 * @Brief Set the strategy for a given prefix
 *
 * @param prefix Prefix for which we set the strategy
 * @param stretegy_id Index of the strategy to set
 */
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

/**
 * @Brief Enable an hICN for an ip prefix
 *
 * @param prefix Prefix for which we enable hICN
 * @return HICN_ERROR_NONE if hICN was enabled on the prefix
 * HICN_ERROR_ROUTE_NO_LD if the first dpo for the fib entry corresponding to the prefix is not a load_balancer
 * HICN_ERROR_ROUTE_DPO_NO_HICN if the loadbalancer in the vrf HICN already contains a dpo which is not an hICN one
 * HICN_ERROR_ROUTE_MLT_LD if there are more than a dpo in the vpp loadbalancer
 */
int
hicn_route_enable (fib_prefix_t *prefix);

/**
 * @Brief Disable an hICN for an ip prefix. If hICN wasn't enable on the prefix
 * nothing happens and it returns HICN_ERROR_ROUTE_NOT_FOUND
 *
 * @param prefix Prefix for which we disable hICN
 */
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
