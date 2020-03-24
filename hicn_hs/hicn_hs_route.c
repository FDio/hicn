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

#include <plugins/hicn_hs/hicn_hs.h>
#include <plugins/hicn_hs/hicn_hs_route.h>

#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vlib/global_funcs.h>
#include <vnet/dpo/drop_dpo.h>

#define HICN_HS_FIB_TABLE 0

#define FIB_SOURCE_HICN_HS 0x04	//Right after the FIB_SOURCE_INTERFACE priority

fib_source_t hicn_hs_fib_src;

void
hicn_hs_route_init ()
{
  hicn_hs_fib_src = fib_source_allocate ("hicn_hs", FIB_SOURCE_HICN_HS, FIB_SOURCE_BH_API);
}

always_inline int
hicn_route_get_dpo (const fib_prefix_t * prefix,
		    const dpo_id_t ** hicn_dpo, u32 * fib_index)
{
  //fib_prefix_t fib_pfx;
  const dpo_id_t *load_balance_dpo_id;
  const dpo_id_t *former_dpo_id;
  int found = 0, ret = HICN_HS_ERROR_ROUTE_NOT_FOUND;
  fib_node_index_t fib_entry_index;

  /* Check if the route already exist in the fib */
  /*
   * ASSUMPTION: we use table 0 which is the default table and it is
   * already existing and locked
   */
  *fib_index = fib_table_find_or_create_and_lock (prefix->fp_proto,
						  HICN_HS_FIB_TABLE,
						  hicn_hs_fib_src);
  fib_entry_index = fib_table_lookup_exact_match (*fib_index, prefix);

  if (fib_entry_index != FIB_NODE_INDEX_INVALID)
    {
      /* Route already existing. We need to update the dpo. */
      load_balance_dpo_id =
	fib_entry_contribute_ip_forwarding (fib_entry_index);

      /* The dpo is not a load balance dpo as expected */
      if (load_balance_dpo_id->dpoi_type != DPO_LOAD_BALANCE)
	ret = HICN_HS_ERROR_ROUTE_NO_LB_DPO;
      else
	{
	  /* former_dpo_id is a load_balance dpo */
	  load_balance_t *lb =
	    load_balance_get (load_balance_dpo_id->dpoi_index);

	  /* FIB entry exists but there is no hicn_hs dpo. */
	  ret = HICN_HS_ERROR_ROUTE_DPO_NO_HICN;
	  for (int i = 0; i < lb->lb_n_buckets && !found; i++)
	    {
	      former_dpo_id = load_balance_get_bucket_i (lb, i);

	      if (dpo_is_hicn_hs (former_dpo_id))
		{
		  *hicn_dpo = former_dpo_id;
		  ret = HICN_HS_ERROR_NONE;
		  found = 1;
		}
	    }
	}
    }
  /*
   * Remove the lock from the table. We keep one lock per route, not
   * per dpo
   */
  fib_table_unlock (*fib_index, prefix->fp_proto, hicn_hs_fib_src);

  return ret;
}

/* Add a new route for a name prefix */
always_inline
int hicn_hs_route_add_flags (const fib_prefix_t * prefix, const dpo_id_t *dpo, fib_entry_flag_t flags)
{
  CLIB_UNUSED(vlib_main_t *vm) = vlib_get_main ();
  int ret = HICN_HS_ERROR_NONE;
  u32 fib_index;
  const dpo_id_t *_dpo;

  ret = hicn_route_get_dpo (prefix, &_dpo, &fib_index);

  if (ret == HICN_HS_ERROR_ROUTE_NOT_FOUND)
    {
      /* Here is where we create the "via" like route */
      /*
       * For the moment we use the global one the prefix you want
       * to match Neale suggested -- FIB_SOURCE_HICN the client
       * that is adding them -- no easy explanation at this time…
       */
      fib_node_index_t new_fib_node_index =
	fib_table_entry_special_dpo_add (fib_index,
					 prefix,
					 hicn_hs_fib_src,
					 flags,
					 dpo);

      /* We added a route, therefore add one lock to the table */
      fib_table_lock (fib_index, prefix->fp_proto, hicn_hs_fib_src);

      ret =
	(new_fib_node_index !=
	 FIB_NODE_INDEX_INVALID) ? HICN_HS_ERROR_NONE :
	HICN_HS_ERROR_ROUTE_NO_INSERT;
    }

  return ret;
}

int
hicn_hs_route_add (const fib_prefix_t * prefix, const dpo_id_t *dpo)
{
  return hicn_hs_route_add_flags(prefix, dpo, (FIB_ENTRY_FLAG_EXCLUSIVE |
					       FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT));
}

clib_error_t *
hicn_hs_set_local_prefix(const fib_prefix_t * prefix)
{
  clib_error_t * ret = 0;
  int rv;
  const dpo_id_t *drop_dpo = drop_dpo_get(prefix->fp_proto == FIB_PROTOCOL_IP4 ? DPO_PROTO_IP4 : DPO_PROTO_IP6);
  rv = hicn_hs_route_add_flags(prefix, drop_dpo, (FIB_ENTRY_FLAG_EXCLUSIVE | FIB_ENTRY_FLAG_LOCAL | FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT));

  if (rv)
    ret = clib_error_return (0, "Error: %s", hicn_hs_error_strings[rv]);
  
  return ret;
}

int
hicn_route_del (fib_prefix_t * prefix)
{
  const dpo_id_t *hicn_dpo_id;
  int ret = HICN_HS_ERROR_NONE;
  u32 fib_index;

  /* Remove the fib entry only if the dpo is of type hicn */
  ret = hicn_route_get_dpo (prefix, &hicn_dpo_id, &fib_index);

  if (ret == HICN_HS_ERROR_NONE)
    {
      fib_table_entry_special_remove (HICN_HS_FIB_TABLE, prefix, hicn_hs_fib_src);

      /*
       * Remove the lock from the table. We keep one lock per route
       */
      fib_table_unlock (fib_index, prefix->fp_proto, hicn_hs_fib_src);
    }
  
  // Remember to remove the lock from the table when removing the entry
  return ret;
}