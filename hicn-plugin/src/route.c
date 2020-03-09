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

#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vlib/global_funcs.h>

#include "strategy_dpo_ctx.h"
#include "strategy_dpo_manager.h"
#include "strategy.h"
#include "faces/face.h"
#include "error.h"
#include "strategies/dpo_mw.h"

#define FIB_SOURCE_HICN 0x04	//Right after the FIB_SOURCE_INTERFACE priority

fib_source_t hicn_fib_src;

int
hicn_route_get_dpo (const fib_prefix_t * prefix,
		    const dpo_id_t ** hicn_dpo, u32 * fib_index)
{
  //fib_prefix_t fib_pfx;
  const dpo_id_t *load_balance_dpo_id;
  const dpo_id_t *former_dpo_id;
  int found = 0, ret = HICN_ERROR_ROUTE_NOT_FOUND;
  fib_node_index_t fib_entry_index;

  /* Check if the route already exist in the fib */
  /*
   * ASSUMPTION: we use table 0 which is the default table and it is
   * already existing and locked
   */
  *fib_index = fib_table_find_or_create_and_lock (prefix->fp_proto,
						  HICN_FIB_TABLE,
						  hicn_fib_src);
  fib_entry_index = fib_table_lookup_exact_match (*fib_index, prefix);

  if (fib_entry_index != FIB_NODE_INDEX_INVALID)
    {
      /* Route already existing. We need to update the dpo. */
      load_balance_dpo_id =
	fib_entry_contribute_ip_forwarding (fib_entry_index);

      /* The dpo is not a load balance dpo as expected */
      if (load_balance_dpo_id->dpoi_type != DPO_LOAD_BALANCE)
	ret = HICN_ERROR_ROUTE_NO_LD;
      else
	{
	  /* former_dpo_id is a load_balance dpo */
	  load_balance_t *lb =
	    load_balance_get (load_balance_dpo_id->dpoi_index);

	  /* FIB entry exists but there is no hicn dpo. */
	  ret = HICN_ERROR_ROUTE_DPO_NO_HICN;
	  for (int i = 0; i < lb->lb_n_buckets && !found; i++)
	    {
	      former_dpo_id = load_balance_get_bucket_i (lb, i);

	      if (dpo_is_hicn (former_dpo_id))
		{
		  *hicn_dpo = former_dpo_id;
		  ret = HICN_ERROR_NONE;
		  found = 1;
		}
	    }
	}
    }
  /*
   * Remove the lock from the table. We keep one lock per route, not
   * per dpo
   */
  fib_table_unlock (*fib_index, prefix->fp_proto, hicn_fib_src);

  return ret;
}

int
hicn_route_add_nhops (hicn_face_id_t * face_id, u32 len,
		      const fib_prefix_t * prefix)
{
  const dpo_id_t *hicn_dpo_id;
  int ret = HICN_ERROR_NONE;
  dpo_id_t faces_dpo_tmp[HICN_PARAM_FIB_ENTRY_NHOPS_MAX];
  int n_face_dpo = 0;
  const hicn_dpo_vft_t *dpo_vft;
  u32 fib_index;
  vlib_main_t *vm = vlib_get_main ();
  hicn_face_vft_t *face_vft = NULL;

  if (face_id == NULL)
    {
      return HICN_ERROR_ROUTE_INVAL;
    }
  /*
   * Check is the faces are available, otherwise skip the face
   * id_adjacency existance is not checked. It should be checked before
   * sending a packet out
   */
  for (int i = 0; i < clib_min (HICN_PARAM_FIB_ENTRY_NHOPS_MAX, len); i++)
    {
      hicn_face_t *face = hicn_dpoi_get_from_idx (face_id[i]);
      face_vft = hicn_face_get_vft (face->shared.face_type);
      dpo_id_t face_dpo = DPO_INVALID;
      face_vft->hicn_face_get_dpo (face, &face_dpo);

      if (!dpo_id_is_valid (&face_dpo))
	{
	  vlib_cli_output (vm, "Face %d not found, skip...\n", face_id[i]);
	  return ret;
	}
      else
	{
	  faces_dpo_tmp[n_face_dpo++] = face_dpo;
	}
    }

  ret = hicn_route_get_dpo (prefix, &hicn_dpo_id, &fib_index);

  if (ret == HICN_ERROR_NONE)
    {
      for (int i = 0; i < n_face_dpo && (ret == HICN_ERROR_NONE); i++)
	{
	  u32 vft_id = hicn_dpo_get_vft_id (hicn_dpo_id);
	  dpo_vft = hicn_dpo_get_vft (vft_id);
	  ret = dpo_vft->hicn_dpo_add_update_nh (&faces_dpo_tmp[i],
						 hicn_dpo_id->dpoi_index);
	}
    }
  return ret;
}

/* Add a new route for a name prefix */
int
hicn_route_add (hicn_face_id_t * face_id, u32 len,
		const fib_prefix_t * prefix)
{
  dpo_id_t dpo = DPO_INVALID;
  const dpo_id_t *hicn_dpo_id;
  int ret = HICN_ERROR_NONE;
  dpo_id_t face_dpo_tmp[HICN_PARAM_FIB_ENTRY_NHOPS_MAX];
  int n_face_dpo = 0;
  index_t dpo_idx;
  u32 fib_index;
  vlib_main_t *vm = vlib_get_main ();
  hicn_face_vft_t *face_vft = NULL;

  if (face_id == NULL || !hicn_dpoi_idx_is_valid (*face_id))
    {
      return HICN_ERROR_ROUTE_INVAL;
    }
  /*
   * Check is the faces are available, otherwise skip the face
   * id_adjacency existance is not checked. It should be checked before
   * sending a packet out
   */
  for (int i = 0; i < clib_min (HICN_PARAM_FIB_ENTRY_NHOPS_MAX, len); i++)
    {
      hicn_face_t *face = hicn_dpoi_get_from_idx (face_id[i]);
      face_vft = hicn_face_get_vft (face->shared.face_type);
      dpo_id_t face_dpo = DPO_INVALID;
      face_vft->hicn_face_get_dpo (face, &face_dpo);

      if (!dpo_id_is_valid (&face_dpo))
	{
	  vlib_cli_output (vm, "Face %d not found, skip...\n", face_id[i]);
	  return ret;
	}
      else
	{
	  face_dpo_tmp[n_face_dpo++] = face_dpo;
	}
    }

  ret = hicn_route_get_dpo (prefix, &hicn_dpo_id, &fib_index);

  if (ret == HICN_ERROR_ROUTE_NOT_FOUND)
    {
      dpo_id_t nhops[HICN_PARAM_FIB_ENTRY_NHOPS_MAX];
      for (int i = 0; i < n_face_dpo; i++)
	{
	  clib_memcpy (&nhops[i], &face_dpo_tmp[i], sizeof (dpo_id_t));
	}

      default_dpo.hicn_dpo_create (prefix->fp_proto, nhops, n_face_dpo,
				     &dpo_idx);

      /* the value we got when we registered */
      /*
       * This should be taken from the name?!? the index of the
       * object
       */
      dpo_set (&dpo,
	       default_dpo.hicn_dpo_get_type (),
	       (ip46_address_is_ip4 (&prefix->fp_addr) ? DPO_PROTO_IP4 :
		DPO_PROTO_IP6), dpo_idx);

      /* Here is where we create the "via" like route */
      /*
       * For the moment we use the global one the prefix you want
       * to match Neale suggested -- FIB_SOURCE_HICN the client
       * that is adding them -- no easy explanation at this time…
       */
      fib_node_index_t new_fib_node_index =
	fib_table_entry_special_dpo_add (fib_index,
					 prefix,
					 hicn_fib_src,
					 FIB_ENTRY_FLAG_EXCLUSIVE,
					 &dpo);

      /* We added a route, therefore add one lock to the table */
      fib_table_lock (fib_index, prefix->fp_proto, hicn_fib_src);

      dpo_unlock (&dpo);
      ret =
	(new_fib_node_index !=
	 FIB_NODE_INDEX_INVALID) ? HICN_ERROR_NONE :
	HICN_ERROR_ROUTE_NO_INSERT;

      /*
       * TODO: we might want to store the fib index in the face.
       * This will help to update the fib entries when a face is
       * deleted. Fib_index_t is returned from
       * fib_table_entry_special_dpo_add.
       */
    }
  else if (ret == HICN_ERROR_NONE)
    {
      ret = hicn_route_add_nhops (face_id, len, prefix);
    }
  return ret;
}

int
hicn_route_del (fib_prefix_t * prefix)
{
  const dpo_id_t *hicn_dpo_id;
  int ret = HICN_ERROR_NONE;
  u32 fib_index;

  /* Remove the fib entry only if the dpo is of type hicn */
  ret = hicn_route_get_dpo (prefix, &hicn_dpo_id, &fib_index);

  if (ret == HICN_ERROR_NONE)
    {
      fib_table_entry_special_remove (HICN_FIB_TABLE, prefix, hicn_fib_src);

      /*
       * Remove the lock from the table. We keep one lock per route
       */
      fib_table_unlock (fib_index, prefix->fp_proto, hicn_fib_src);
    }
  //Remember to remove the lock from the table when removing the entry
  return ret;
}

int
hicn_route_del_nhop (fib_prefix_t * prefix, hicn_face_id_t face_id)
{
  const dpo_id_t *hicn_dpo_id;
  int ret;
  u32 vft_id;
  const hicn_dpo_vft_t *dpo_vft;
  u32 fib_index;


  ret = hicn_route_get_dpo (prefix, &hicn_dpo_id, &fib_index);

  /* Check if the dpo is an hicn_dpo_t */
  if (ret == HICN_ERROR_NONE)
    {
      vft_id = hicn_dpo_get_vft_id (hicn_dpo_id);
      dpo_vft = hicn_dpo_get_vft (vft_id);
      ret = dpo_vft->hicn_dpo_del_nh (face_id, hicn_dpo_id->dpoi_index);

      hicn_dpo_ctx_t *dpo_ctx =
	hicn_strategy_dpo_ctx_get (hicn_dpo_id->dpoi_index);

      if (ret == HICN_ERROR_NONE && !dpo_ctx->entry_count)
	ret = hicn_route_del (prefix);
    }
  //Remember to remove the lock from the table when removing the entry
  return ret;
}

int
hicn_route_set_strategy (fib_prefix_t * prefix, u8 strategy_id)
{
  const dpo_id_t *hicn_dpo_id;
  dpo_id_t new_dpo_id = DPO_INVALID;
  int ret;
  hicn_dpo_ctx_t *old_hicn_dpo_ctx;
  const hicn_dpo_vft_t *new_dpo_vft;
  index_t new_hicn_dpo_idx;
  u32 fib_index;

  ret = hicn_route_get_dpo (prefix, &hicn_dpo_id, &fib_index);

  if (ret == HICN_ERROR_NONE)
    {
      old_hicn_dpo_ctx = hicn_strategy_dpo_ctx_get (hicn_dpo_id->dpoi_index);

      new_dpo_vft = hicn_dpo_get_vft_from_id (strategy_id);

      if (new_dpo_vft == NULL || old_hicn_dpo_ctx == NULL)
	return HICN_ERROR_STRATEGY_NOT_FOUND;

      /* Create a new dpo for the new strategy */
      new_dpo_vft->hicn_dpo_create (hicn_dpo_id->dpoi_proto,
				    old_hicn_dpo_ctx->next_hops,
				    old_hicn_dpo_ctx->entry_count,
				    &new_hicn_dpo_idx);

      /* the value we got when we registered */
      dpo_set (&new_dpo_id,
	       new_dpo_vft->hicn_dpo_get_type (),
	       (ip46_address_is_ip4 (&prefix->fp_addr) ? DPO_PROTO_IP4 :
		DPO_PROTO_IP6), new_hicn_dpo_idx);

      /* Here is where we create the "via" like route */
      /*
       * For the moment we use the global one the prefix you want
       * to match Neale suggested -- FIB_SOURCE_HICN the client
       * that is adding them -- no easy explanation at this time…
       */
      fib_node_index_t new_fib_node_index =
	fib_table_entry_special_dpo_update (fib_index,
					    prefix,
					    hicn_fib_src,
					    FIB_ENTRY_FLAG_EXCLUSIVE,
					    &new_dpo_id);

      dpo_unlock (&new_dpo_id);
      ret =
	(new_fib_node_index !=
	 FIB_NODE_INDEX_INVALID) ? HICN_ERROR_NONE :
	HICN_ERROR_ROUTE_NOT_UPDATED;
    }
  //Remember to remove the lock from the table when removing the entry
  return ret;

}

void
hicn_route_init ()
{
  hicn_fib_src = fib_source_allocate ("hicn",
				      FIB_SOURCE_HICN, FIB_SOURCE_BH_API);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
