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

/*
 * Copyright (c) 2017-2019 by cisco systems inc. All rights reserved.
 *
 */

#include <dlfcn.h>

#include <vlib/vlib.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip4.h>	//ip4_add_del_ip_address
#include <vnet/ip/ip6.h>	//ip6_add_del_ip_address
#include <vnet/fib/fib_types.h>	//FIB_PROTOCOL_IP4/6, FIB_NODE_INDEX_INVALID
#include <vnet/fib/fib_entry.h>	//FIB_SOURCE_PRIORITY_HI
#include <vnet/fib/fib_table.h>
#include <vppinfra/format.h>
#include <vnet/interface.h>	//appif_flags
#include <vnet/interface_funcs.h>	//vnet_sw_interface_set_flags

#include "address_mgr.h"
#include "../../hicn.h"
#include "../../infra.h"
#include "../../error.h"
#include "../face.h"
#include "../../strategy_dpo_ctx.h"
#include "../../route.h"

typedef struct address_mgr_main_s
{
  ip4_address_t next_ip4_local_addr;
  ip6_address_t next_ip6_local_addr;
} address_mgr_main_t;

address_mgr_main_t address_mgr_main;

static void
increment_v4_address (ip4_address_t * a, u32 val)
{
  u32 v;

  v = clib_net_to_host_u32 (a->as_u32) + val;
  a->as_u32 = clib_host_to_net_u32 (v);
}

static void
increment_v6_address (ip6_address_t * a, u64 val)
{
  u64 v;

  v = clib_net_to_host_u64 (a->as_u64[1]) + val;
  a->as_u64[1] = clib_host_to_net_u64 (v);
}

void
get_two_ip4_addresses (ip4_address_t * appif_addr, ip4_address_t * nh_addr)
{
  /* We want two consecutives address that fall into a /31 mask */
  if (address_mgr_main.next_ip4_local_addr.as_u8[3] & 0x01)
    increment_v4_address (&(address_mgr_main.next_ip4_local_addr), 1);

  *appif_addr = address_mgr_main.next_ip4_local_addr;
  increment_v4_address (&(address_mgr_main.next_ip4_local_addr), 1);
  *nh_addr = address_mgr_main.next_ip4_local_addr;
  fib_prefix_t fib_pfx;
  fib_node_index_t fib_entry_index = FIB_NODE_INDEX_INVALID;
  u32 fib_index;

  fib_pfx.fp_proto = FIB_PROTOCOL_IP4;
  fib_pfx.fp_len = ADDR_MGR_IP4_LEN;
  /* At this point the face exists in the face table */
  do
    {
      /* Check if the route already exist in the fib */
      fib_pfx.fp_addr = to_ip46 ( /* is_v6 */ 0, appif_addr->as_u8);
      fib_index = fib_table_find_or_create_and_lock (fib_pfx.fp_proto,
						     HICN_FIB_TABLE,
						     FIB_SOURCE_PRIORITY_HI);
      fib_entry_index = fib_table_lookup_exact_match (fib_index, &fib_pfx);
      fib_table_unlock (fib_index, fib_pfx.fp_proto, FIB_SOURCE_PRIORITY_HI);
      if (fib_entry_index != FIB_NODE_INDEX_INVALID)
	{
	  fib_pfx.fp_addr = to_ip46 ( /* is_v6 */ 0, nh_addr->as_u8);
	  fib_index = fib_table_find_or_create_and_lock (fib_pfx.fp_proto,
							 HICN_FIB_TABLE,
							 FIB_SOURCE_PRIORITY_HI);
	  fib_entry_index =
	    fib_table_lookup_exact_match (fib_index, &fib_pfx);
	  fib_table_unlock (fib_index, fib_pfx.fp_proto,
			    FIB_SOURCE_PRIORITY_HI);
	}
      if (fib_entry_index != FIB_NODE_INDEX_INVALID)
	{
	  increment_v4_address (appif_addr, 2);
	  increment_v4_address (nh_addr, 2);
	}
    }
  while (fib_entry_index != FIB_NODE_INDEX_INVALID);

  address_mgr_main.next_ip4_local_addr = *nh_addr;
  increment_v4_address (&(address_mgr_main.next_ip4_local_addr), 1);
}

void
get_two_ip6_addresses (ip6_address_t * appif_addr, ip6_address_t * nh_addr)
{

  /* We want two consecutives address that fall into a /127 mask */
  if (address_mgr_main.next_ip6_local_addr.as_u8[15] & 0x01)
    increment_v6_address (&(address_mgr_main.next_ip6_local_addr), 1);

  *appif_addr = address_mgr_main.next_ip6_local_addr;
  increment_v6_address (&(address_mgr_main.next_ip6_local_addr), 1);
  *nh_addr = address_mgr_main.next_ip6_local_addr;


  fib_prefix_t fib_pfx;
  fib_node_index_t fib_entry_index = FIB_NODE_INDEX_INVALID;
  u32 fib_index;

  fib_pfx.fp_proto = FIB_PROTOCOL_IP6;
  fib_pfx.fp_len = ADDR_MGR_IP6_LEN;

  fib_index = fib_table_find (fib_pfx.fp_proto, 0);

  /* At this point the face exists in the face table */
  do
    {
      /* Check if the route already exist in the fib */
      fib_pfx.fp_addr = to_ip46 ( /* is_v6 */ 1, appif_addr->as_u8);

      fib_entry_index = fib_table_lookup_exact_match (fib_index, &fib_pfx);
      //fib_table_unlock (fib_index, fib_pfx.fp_proto, FIB_SOURCE_PRIORITY_HI);
      if (fib_entry_index != FIB_NODE_INDEX_INVALID)
	{
	  fib_pfx.fp_addr = to_ip46 ( /* is_v6 */ 0, nh_addr->as_u8);

	  fib_entry_index =
	    fib_table_lookup_exact_match (fib_index, &fib_pfx);
          //	  fib_table_unlock (fib_index, fib_pfx.fp_proto,
          //		    FIB_SOURCE_PRIORITY_HI);
	}
      if (fib_entry_index != FIB_NODE_INDEX_INVALID)
	{
	  increment_v6_address (appif_addr, 2);
	  increment_v6_address (nh_addr, 2);
	}
    }
  while (fib_entry_index != FIB_NODE_INDEX_INVALID);

  address_mgr_main.next_ip6_local_addr = *nh_addr;
  increment_v6_address (&(address_mgr_main.next_ip6_local_addr), 1);
}

ip4_address_t
get_ip4_address ()
{
  ip4_address_t *prefix = &address_mgr_main.next_ip4_local_addr;
  fib_prefix_t fib_pfx;
  fib_node_index_t fib_entry_index = FIB_NODE_INDEX_INVALID;
  u32 fib_index;

  fib_pfx.fp_proto = FIB_PROTOCOL_IP4;
  fib_pfx.fp_len = ADDR_MGR_IP4_LEN;
  /* At this point the face exists in the face table */
  do
    {
      /* Check if the route already exist in the fib */
      fib_pfx.fp_addr = to_ip46 ( /* is_v6 */ 0, prefix->as_u8);
      fib_index = fib_table_find_or_create_and_lock (fib_pfx.fp_proto,
						     HICN_FIB_TABLE,
						     FIB_SOURCE_PRIORITY_HI);
      fib_entry_index = fib_table_lookup_exact_match (fib_index, &fib_pfx);
      fib_table_unlock (fib_index, fib_pfx.fp_proto, FIB_SOURCE_PRIORITY_HI);
      increment_v4_address (prefix, 1);
    }
  while (fib_entry_index != FIB_NODE_INDEX_INVALID);

  return fib_pfx.fp_addr.ip4;
}

ip6_address_t
get_ip6_address ()
{
  ip6_address_t *prefix = &address_mgr_main.next_ip6_local_addr;
  fib_prefix_t fib_pfx;
  fib_node_index_t fib_entry_index = FIB_NODE_INDEX_INVALID;
  u32 fib_index;

  fib_pfx.fp_proto = FIB_PROTOCOL_IP6;
  fib_pfx.fp_len = ADDR_MGR_IP6_LEN;
  /* At this point the face exists in the face table */
  do
    {
      /* Check if the route already exist in the fib */
      fib_pfx.fp_addr = to_ip46 ( /* is_v6 */ 1, prefix->as_u8);
      fib_index = fib_table_find_or_create_and_lock (fib_pfx.fp_proto,
						     HICN_FIB_TABLE,
						     FIB_SOURCE_PRIORITY_HI);
      fib_entry_index = fib_table_lookup_exact_match (fib_index, &fib_pfx);
      fib_table_unlock (fib_index, fib_pfx.fp_proto, FIB_SOURCE_PRIORITY_HI);
      increment_v6_address (prefix, 1);
    }
  while (fib_entry_index != FIB_NODE_INDEX_INVALID);

  return fib_pfx.fp_addr.ip6;
}

void
address_mgr_init ()
{

  address_mgr_main.next_ip4_local_addr.as_u8[0] = 169;
  address_mgr_main.next_ip4_local_addr.as_u8[1] = 254;
  address_mgr_main.next_ip4_local_addr.as_u8[2] = 1;
  address_mgr_main.next_ip4_local_addr.as_u8[3] = 1;

  ip6_address_set_zero (&address_mgr_main.next_ip6_local_addr);
  address_mgr_main.next_ip6_local_addr.as_u16[0] =
    clib_host_to_net_u16 (0xfc00);
  address_mgr_main.next_ip6_local_addr.as_u8[15] = 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
