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

#ifndef __HICN_PG_H__
#define __HICN_PG_H__


/**
 * @File Packet generator for hICN
 *
 * The packet generator is made of two entities, a client and a server.
 * The client issues interests at high speed and the server satisfy each
 * interest it receives with the corresponding data.
 * The packet generator is made of three nodes:
 * - hicnpg-interest that receives packets from a packet generator interface
 *   and manipulate them to generate interests based on the given configuration.
 *   This node runs at the client side.
 * - hicnpg-data that receives data packets at the client side and counts them.
 *   This is useful for statistics. The "show err" command will give the number
 *   of interest issued and data received at the client side
 * - hicnpg-server that recevies and interest and replies with the corresponding
 *   data. The data is generated from the interest switching the src and destination
 *   address in the packet and appending a payload to the packet.
 *
 *
 * These three nodes are inserted in the vlib graph in the following manner:
 * - hicnpg-interest is added as a possible next node of the pg-input node. The packet
 *   generator stream then specifies it as next node.
 * - hicnpg-data is added as next hop of the ip4/6-unicast node exploiting the corresponding
 *   feature and it runs before the ip4/6-inacl node. In this way, every packet that is
 *   received through an interface on which this feature is enabled is sent to this node.
 * - hicnpg-server is added as next hop of the ip4/6-unicast using the corresponding
 *   feature and it runs before the ip4/6-inacl node. In this way, every packet that is
 *   received through an interface on which this feature is enabled is sent to this node.
 *
 * An example of how to use the pg for hicn is available in the documentation.
 */

/**
 * @brief hICN packet generator main for the pg client nodes
 *
 * It stores the configuration and make it availables to the pg client nodes.
 */
typedef struct hicnpg_main_s
{
  u32 index; //used to compute the sequence number
  fib_prefix_t * pgen_clt_hicn_name; //hICN name to put in the destiantion addess of an interest
  u32 index_ifaces; /* used to mimic interests coming from different consumer */
  u32 n_ifaces;     /* The source address will change from interest to interest */
                    /* index_ifaces is used to keep a global reference to the iface used */
                    /* and it is incremented when we want to change "consumer" */
                    /* n_ifaces identifies how many consumers to simulate */
  u32 max_seq_number; //Use to limit the max sequence number
  u32 n_flows; //Use to simulate multiple flows (a flow always have the same hICN name)
  ip46_address_t pgen_clt_src_addr; //Source addess base to use in the interest

  u16 interest_lifetime; // Interest lifetime
  u32 sw_if; //Interface where to send interest and receives data
} hicnpg_main_t;

extern hicnpg_main_t hicnpg_main;

/**
 * @brief hICN packet generator main for the pg server node
 *
 * It stores the configuration and make it availables to the pg server node.
 */
typedef struct hicnpg_server_main_s
{
  u32 node_index;
  /* Arbitrary content */
  u32 pgen_svr_buffer_idx;
  fib_prefix_t * pgen_srv_hicn_name;
} hicnpg_server_main_t;

extern hicnpg_server_main_t hicnpg_server_main;

extern vlib_node_registration_t hicn_pg_interest_node;
extern vlib_node_registration_t hicn_pg_data_node;

#endif // __HICN_PG_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
