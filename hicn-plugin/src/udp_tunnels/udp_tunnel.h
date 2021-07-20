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

#ifndef __UDP_TUNNEL__
#define __UDP_TUNNEL__

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <vnet/udp/udp_encap.h>

/**
 * @file udp_tunnel.h
 *
 * This file implements bidirectional udp tunnels. Udp tunnels exploit
 * the udp encap functionality in vpp. In particular, a udp tunnel creates
 * an udp encap object with the information for encapsulating packets and it
 * implements the udp decap node. The udp decap node checks if a udp tunnel
 * exists before performing the decapsulation. If the tunnel does not exist the
 * packet is dropped.
 */

#define UDP_TUNNEL_INVALID ~0

extern dpo_type_t dpo_type_udp_ip4;
extern dpo_type_t dpo_type_udp_ip6;

extern vlib_node_registration_t udp4_decap_node;
extern vlib_node_registration_t udp6_decap_node;

/**
 * @brief Create a udp tunnel
 *
 * @param proto FIB_PROTOCOL_IP4 or FIB_PROTOCOL_IP6
 * @param fib_index fib index to add to the udp encap
 * @param src_ip source address of the tunnel
 * @param dst_ip destination address of the tunnel
 * @param src_port source port
 * @param src_port destination port
 * @param flags flags for the udp encap
 *
 * @return return the id of the tunnel
 */
u32 udp_tunnel_add (fib_protocol_t proto, index_t fib_index,
		    const ip46_address_t *src_ip, const ip46_address_t *dst_ip,
		    u16 src_port, u16 dst_port, udp_encap_fixup_flags_t flags);

/**
 * @brief Retrieve the index of a udp tunnel (same id of the udp encap)
 *
 * @param src_ip source address of the tunnel
 * @param dst_ip destination address of the tunnel
 * @param src_port source port
 * @param src_port destination port
 *
 * @return id of the udp tunnel/encap
 */
u32 udp_tunnel_get (const ip46_address_t *src_ip, const ip46_address_t *dst_ip,
		    u16 src_port, u16 dst_port);

/**
 * @brief Delete a udp tunnel
 *
 * @param proto FIB_PROTOCOL_IP4 or FIB_PROTOCOL_IP6
 * @param fib_index fib index to add to the udp encap
 * @param src_ip source address of the tunnel
 * @param dst_ip destination address of the tunnel
 * @param src_port source port
 * @param src_port destination port
 * @param flags flags for the udp encap
 *
 * @return HICN_ERROR_UDP_TUNNEL_NOT_FOUND if the tunnel was not found
 *         or HICN_ERROR_NONE if the tunnel has been deleted
 */
int udp_tunnel_del (fib_protocol_t proto, index_t fib_index,
		    const ip46_address_t *src_ip, const ip46_address_t *dst_ip,
		    u16 src_port, u16 dst_port, udp_encap_fixup_flags_t flags);

/**
 * @brief Add a udp tunnel from an existing udp encap
 *
 * @param uei index of the udp encap object
 * @param proto DPO_PROTO_IP6 or DPO_PROTO_IP4
 */
void udp_tunnel_add_existing (index_t uei, dpo_proto_t proto);

/**
 * @brief Init the udp tunnel module
 *
 */
void udp_tunnel_init ();

#endif
