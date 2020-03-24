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

#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vlib/global_funcs.h>


/* Add a new route for a name prefix */
always_inline int
hicn_hs_route_add (const fib_prefix_t * prefix, u32 prefix_len, hicn_face_id_t * face_id)
{
  dpo_id_t dpo = DPO_INVALID;
  const dpo_id_t *dpo_id;
  int ret = HICN_HS_ERROR_NONE;
//   dpo_id_t face_dpo_tmp[HICN_PARAM_FIB_ENTRY_NHOPS_MAX];
//   int n_face_dpo = 0;
  index_t dpo_idx;
  u32 fib_index;
  vlib_main_t *vm = vlib_get_main ();

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
	  hicn_face_t *face =
	    hicn_dpoi_get_from_idx (face_dpo_tmp[i].dpoi_index);
	  //Disable feature on the interface
	  if (prefix->fp_proto == FIB_PROTOCOL_IP4)
	    vnet_feature_enable_disable ("ip4-local", "hicn-data-input-ip4",
					 face->shared.sw_if, 1, 0, 0);
	  else if (prefix->fp_proto == FIB_PROTOCOL_IP6)
	    vnet_feature_enable_disable ("ip6-local", "hicn-data-input-ip6",
					 face->shared.sw_if, 1, 0, 0);
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
					 (FIB_ENTRY_FLAG_EXCLUSIVE |
					  FIB_ENTRY_FLAG_LOOSE_URPF_EXEMPT),
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