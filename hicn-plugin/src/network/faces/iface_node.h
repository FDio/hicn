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

#ifndef __HICN_IFACE_NODE_H__
#define __HICN_IFACE_NODE_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

/**
 * @file iface_node.h
 *
 * Implements the input and output iface nodes. Input iface nodes
 * process incoming interests while output face nodes process outgoing
 * data packets.
 *
 * Input iface nodes follow ip-lookup nodes and their purpose
 * is to create (or retrieve if already existing) the list incoming face
 * for each the interest packet.
 * The following node to the input iface nodes is the hicn-interest-pcslookup.
 * Output iface nodes follow the hicn-data-fwd and the hicn-interest-hitcs nodes and
 * they perform the dst nat on each data packet. The node following the
 * output face nodes depends on the adjacency type. In case of ip, the following
 * node is the ip4/6-lookup, in case of tunnels the next node is the one implementing
 * the tunnel encapsulation (udp-encap, mpls, etc).
 */


/**
 * @brief Initialize the ip iface module
 */
void hicn_iface_init (vlib_main_t * vm);

#endif // __HICN_IFACE_IP_NODE_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
