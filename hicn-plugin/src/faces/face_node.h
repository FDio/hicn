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

#ifndef __HICN_FACE_NODE_H__
#define __HICN_FACE_NODE_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>

/**
 * @file face_node.h
 *
 * Implements the input and output face nodes. Input face nodes
 * process incoming data while output face nodes process outgoing
 * interests packets.
 *
 * Input face nodes follow hicn-face-input nodes and their purpose
 * is to retrieve the list of possible incoming faces for each the data packet.
 * The following node to the input face nodes is the hicn-data-pcslookup.
 * Output face nodes follow the strategy and the hicn-interest-hitpit nodes and
 * they perform the src nat on each interest packet. The node following the
 * output face nodes depends on the adjacency type. In case of ip, the following
 * node is the ip-rewrite, in case of tunnels the next node is the one implementing
 * the tunnel encapsulation (udp-encap, mpls, etc).
 */

extern vlib_node_registration_t hicn4_face_input_node;
extern vlib_node_registration_t hicn4_face_output_node;
extern vlib_node_registration_t hicn6_face_input_node;
extern vlib_node_registration_t hicn6_face_output_node;

#endif // __HICN_FACE_NODE_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
