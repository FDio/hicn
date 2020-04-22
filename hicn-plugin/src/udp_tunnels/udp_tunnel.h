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

#define UDP_TUNNEL_INVALID ~0

extern dpo_type_t dpo_type_udp_ip4;
extern dpo_type_t dpo_type_udp_ip6;

extern vlib_node_registration_t udp4_decap_node;
extern vlib_node_registration_t udp6_decap_node;


u32 udp_tunnel_add (fib_protocol_t proto,
                    index_t fib_index,
                    const ip46_address_t * src_ip,
                    const ip46_address_t * dst_ip,
                    u16 src_port,
                    u16 dst_port,
                    udp_encap_fixup_flags_t flags);

u32 udp_tunnel_get(const ip46_address_t * src_ip,
                   const ip46_address_t * dst_ip,
                   u16 src_port,
                   u16 dst_port);

int udp_tunnel_del (fib_protocol_t proto,
                    index_t fib_index,
                    const ip46_address_t * src_ip,
                    const ip46_address_t * dst_ip,
                    u16 src_port,
                    u16 dst_port,
                    udp_encap_fixup_flags_t flags);

void udp_tunnel_add_existing (index_t uei, dpo_proto_t proto);

void udp_tunnel_init();

#endif
