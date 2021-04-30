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

#ifndef __UDP_DECAP_H__
#define __UDP_DECAP_H__

/**
 * @file udp_decap.h
 *
 * Implements the udp decapsulation for udp tunnels
 *
 * Udp decap nodes follow the ip4/6-local nodes and their purpose
 * is to retrieve the udp tunnel for the incoming packet. If a tunnel does
 * not exist the packet is dropped.
 * The following node to the udp decap nodes are the ip4/6-lookup nodes.
 */

extern vlib_node_registration_t udp_decap_node;

#endif // __UDP_DECAP_H__
