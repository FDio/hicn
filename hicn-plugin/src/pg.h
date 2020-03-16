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

#ifndef __HICN_PG_H__
#define __HICN_PG_H__

/* Subnet-mask for punting data in the client node */
#define SUBNET_MASK4 32
#define SUBNET_MASK6 128

typedef struct hicnpg_main_s
{
  u32 index;
  u32 index_ifaces;
  u32 max_seq_number;
  u32 n_flows;
  u32 n_ifaces;
  ip46_address_t pgen_clt_src_addr;
  ip46_address_t pgen_clt_hicn_name;
  u16 interest_lifetime;
} hicnpg_main_t;

extern hicnpg_main_t hicnpg_main;

typedef struct hicnpg_server_main_s
{
  u32 node_index;
  /* Arbitrary content */
  u32 pgen_svr_buffer_idx;
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
