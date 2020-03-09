/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates. Licensed under the
 * Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the
 * License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj.h>

#include "face_ip.h"
#include "face_ip_node.h"
#include "dpo_ip.h"
#include "../../strategy_dpo_manager.h"
#include "../face.h"
#include "../../cache_policies/cs_lru.h"
#include "../../infra.h"
#include "../../hicn.h"
#include "../app/face_prod.h"
#include "../app/face_cons.h"

#include "../../mapme.h"	// HICN_MAPME_EVENT_*
#include "../../mapme_eventmgr.h"	// hicn_mapme_eventmgr_process_node

extern vlib_node_registration_t hicn_mapme_eventmgr_process_node;

u32 strategy_face_ip4_vlib_edge;
u32 strategy_face_ip6_vlib_edge;

void
hicn_face_ip_init (vlib_main_t * vm)
{
  int strategy_nodes_n = hicn_strategy_get_all_available ();

  /* Default Strategy has index 0 and it always exists */
  strategy_face_ip4_vlib_edge = vlib_node_add_next (vm,
						    hicn_strategy_node.index,
						    hicn_face_ip4_output_node.
						    index);

  strategy_face_ip6_vlib_edge = vlib_node_add_next (vm,
						    hicn_strategy_node.index,
						    hicn_face_ip6_output_node.
						    index);
  /*
   * Create and edge between al the other strategy nodes and the
   * ip_encap nodes.
   */
  for (int i = 1; i < strategy_nodes_n; i++)
    {
      u32 temp_index4 = vlib_node_add_next (vm,
					    hicn_strategy_node.index,
					    hicn_face_ip4_output_node.index);
      u32 temp_index6 = vlib_node_add_next (vm,
					    hicn_strategy_node.index,
					    hicn_face_ip6_output_node.index);
      ASSERT (temp_index4 == strategy_face_ip4_vlib_edge);
      ASSERT (temp_index6 == strategy_face_ip6_vlib_edge);
    }

  u32 temp_index4 = vlib_node_add_next (vm,
					hicn_interest_hitpit_node.index,
					hicn_face_ip4_output_node.index);
  u32 temp_index6 = vlib_node_add_next (vm,
					hicn_interest_hitpit_node.index,
					hicn_face_ip6_output_node.index);

  ASSERT (temp_index4 == strategy_face_ip4_vlib_edge);
  ASSERT (temp_index6 == strategy_face_ip6_vlib_edge);


  hicn_dpo_ip_module_init ();

  register_face_type (hicn_face_ip_type, &ip_vft, "ip");
}

int
hicn_face_ip_del (hicn_face_id_t face_id)
{
  hicn_face_t *face = hicn_dpoi_get_from_idx (face_id);
  hicn_face_ip_t *face_ip = (hicn_face_ip_t *) face->data;
  hicn_face_ip_key_t key;
  hicn_face_ip_key_t old_key;
  hicn_face_ip_key_t old_key2;

  if (ip46_address_is_ip4 (&face_ip->local_addr))
    {
      hicn_face_ip4_get_key (&(face_ip->local_addr.ip4), face->shared.sw_if,
			     &key);
      hicn_face_ip_input_faces_t * in_faces_vec = hicn_face_ip4_get_vec(&(face_ip->local_addr.ip4), face->shared.sw_if,
                                                                        &hicn_face_ip_local_hashtb);
      if (in_faces_vec != NULL)
        {
          hicn_face_ip_vec_t * vec = pool_elt_at_index (hicn_vec_pool, in_faces_vec->vec_id);
          u32 index_face = vec_search(*vec, face_id);
          vec_del1(*vec, index_face);

          if (vec_len(*vec) == 0)
            {
              pool_put_index(hicn_vec_pool, in_faces_vec->vec_id);
              mhash_unset (&hicn_face_ip_local_hashtb, &key, (uword *) & old_key);
              vec_free(*vec);
            }
          else
            {
              /* Check if the face we are deleting is the preferred one. */
              /* If so, repleace with another. */
              if (in_faces_vec->face_id == face_id)
                {
                  in_faces_vec->face_id = (*vec)[0];
                }
            }
          hicn_face_ip4_get_key (&(face_ip->remote_addr.ip4), face->shared.sw_if,
                                 &key);
          mhash_unset (&hicn_face_ip_remote_hashtb, &key, (uword *) & old_key2);
        }
    }
  else
    {
      hicn_face_ip6_get_key (&(face_ip->local_addr.ip6), face->shared.sw_if,
			     &key);

      hicn_face_ip_input_faces_t * in_faces_vec = hicn_face_ip6_get_vec(&(face_ip->local_addr.ip6), face->shared.sw_if,
                                                                      &hicn_face_ip_local_hashtb);
      if (in_faces_vec != NULL)
        {
          hicn_face_ip_vec_t * vec = pool_elt_at_index (hicn_vec_pool, in_faces_vec->vec_id);
          u32 index_face = vec_search(*vec, face_id);
          vec_del1(*vec, index_face);

          if (vec_len(*vec) == 0)
            {
              pool_put(hicn_vec_pool, vec);
              mhash_unset (&hicn_face_ip_local_hashtb, &key, (uword *) & old_key);
              vec_free(*vec);
            }
          else
            {
              /* Check if the face we are deleting is the preferred one. */
              /* If so, repleace with another. */
              if (in_faces_vec->face_id == face_id)
                {
                  in_faces_vec->face_id = (*vec)[0];
                }
            }
          hicn_face_ip6_get_key (&(face_ip->remote_addr.ip6), face->shared.sw_if,
                                 &key);
          mhash_unset (&hicn_face_ip_remote_hashtb, &key, (uword *) & old_key);
        }
    }
  return hicn_face_del (face_id);
}

/**
 * @brief Helper for handling midchain adjacencies
 */
void face_midchain_fixup_t (vlib_main_t * vm,
                            const struct ip_adjacency_t_ * adj,
                            vlib_buffer_t * b0,
                            const void *data) {
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = 0;
};

/**
 * @brief Build a rewrite string for the face.
 */
static u8*
face_build_rewrite_i (void)
{
  /*
   * passing the adj code a NULL rewrite means 'i don't have one cos
   * t'other end is unresolved'. That's not the case here. For the mpls
   * tunnel there are just no bytes of encap to apply in the adj. We'll impose
   * the label stack once we choose a path. So return a zero length rewrite.
   */
  u8 *rewrite = NULL;

  vec_validate(rewrite, 0);
  vec_reset_length(rewrite);

  return (rewrite);
}

always_inline int
hicn_face_ip_find_adj (const ip46_address_t * remote_addr,
                       int sw_if, adj_index_t * adj)
{
  fib_prefix_t fib_pfx;
  fib_node_index_t fib_entry_index;
  fib_prefix_from_ip46_addr (remote_addr, &fib_pfx);
  fib_pfx.fp_len = ip46_address_is_ip4(remote_addr)? 32 : 128;
  vnet_link_t link_type = ip46_address_is_ip4(&fib_pfx.fp_addr)? VNET_LINK_IP4 : VNET_LINK_IP6;
  *adj = adj_nbr_find(fib_pfx.fp_proto, link_type, &fib_pfx.fp_addr, sw_if);

  if (*adj == ADJ_INDEX_INVALID)
    {
      u32 fib_index = fib_table_find_or_create_and_lock (fib_pfx.fp_proto,
                                                         HICN_FIB_TABLE,
                                                         FIB_SOURCE_PRIORITY_HI);

      fib_entry_index = fib_table_lookup (fib_index, &fib_pfx);

      if (fib_entry_index == (FIB_NODE_INDEX_INVALID))
        return HICN_ERROR_FACE_IP_ADJ_NOT_FOUND;

      *adj = fib_entry_get_adj (fib_entry_index);
      ip_adjacency_t * temp = NULL;
      if (*adj != ~0)
        temp = adj_get(*adj);

      if (temp == NULL || temp->lookup_next_index <= IP_LOOKUP_NEXT_MIDCHAIN)
        {
          if(sw_if != ~0)
            *adj = adj_nbr_add_or_lock(fib_pfx.fp_proto, link_type, remote_addr, sw_if);
          else
            return HICN_ERROR_FACE_IP_ADJ_NOT_FOUND;
        }
      else
        {
          adj_nbr_midchain_update_rewrite(*adj, &face_midchain_fixup_t, NULL, ADJ_FLAG_NONE, face_build_rewrite_i());
          adj_midchain_delegate_stack(*adj, fib_index, &fib_pfx);
        }
    }

  return HICN_ERROR_NONE;
}

/*
 * Utility that adds a new face cache entry. For the moment we assume that
 * the ip_adjacency has already been set up.
 */
int
hicn_face_ip_add (const ip46_address_t * local_addr,
		  const ip46_address_t * remote_addr,
		  int sw_if, hicn_face_id_t * pfaceid,
                  u8 is_app_prod)
{
  dpo_proto_t dpo_proto;

  /* Check if we found at least one ip address */
  if (ip46_address_is_zero (remote_addr))
    return HICN_ERROR_FACE_NO_GLOBAL_IP;

  hicn_face_flags_t flags = (hicn_face_flags_t) 0;
  flags |= HICN_FACE_FLAGS_FACE;

  hicn_face_t *face;
  if (ip46_address_is_ip4 (local_addr))
    {
      face =
	hicn_face_ip4_get (&(remote_addr->ip4), sw_if,
			   &hicn_face_ip_remote_hashtb);

      /* If remote matches the face we need to check if it is an incomplete face */
      if (face == NULL)
	{
	  hicn_iface_ip_add (local_addr, remote_addr, sw_if, pfaceid);
	  face = hicn_dpoi_get_from_idx (*pfaceid);
	}
      else
	{
	  *pfaceid = hicn_dpoi_get_index (face);
	}

      if (!(face->shared.flags & HICN_FACE_FLAGS_IFACE))
        return HICN_ERROR_FACE_ALREADY_CREATED;

      hicn_face_ip_key_t key;
      hicn_face_ip4_get_key (&(local_addr->ip4), sw_if, &key);

      hicn_face_ip_input_faces_t * in_faces =
	hicn_face_ip4_get_vec (&(local_addr->ip4), sw_if,
                               &hicn_face_ip_local_hashtb);

      if (in_faces == NULL)
        {
          adj_index_t adj;
          int ret = hicn_face_ip_find_adj(remote_addr, sw_if, &adj);
          if (ret != HICN_ERROR_NONE)
            return ret;

          hicn_face_ip_input_faces_t in_faces_temp;
          hicn_face_ip_vec_t *vec;
          pool_get(hicn_vec_pool, vec);
          *vec = vec_new(hicn_face_ip_vec_t, 0);
          u32 index = vec - hicn_vec_pool;
          in_faces_temp.vec_id = index;
          vec_add1(*vec, *pfaceid);

          hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
          clib_memcpy (&ip_face->local_addr, local_addr, sizeof (ip4_address_t));
          clib_memcpy (&ip_face->remote_addr, remote_addr,
                       sizeof (ip4_address_t));
          face->shared.sw_if = sw_if;
          face->shared.flags = flags;
          face->shared.adj = adj;

          dpo_proto = DPO_PROTO_IP4;

          in_faces_temp.face_id = *pfaceid;

          mhash_set_mem (&hicn_face_ip_local_hashtb, &key, (uword *) &in_faces_temp, 0);
        }
      else
        {
          hicn_face_ip_vec_t * vec = pool_elt_at_index(hicn_vec_pool, in_faces->vec_id);

          /* */
          if (vec_search(*vec, *pfaceid) != ~0)
            return HICN_ERROR_FACE_ALREADY_CREATED;

          adj_index_t adj;
          int ret = hicn_face_ip_find_adj(remote_addr, sw_if, &adj);
          if (ret != HICN_ERROR_NONE)
            return ret;

          vec_add1(*vec, *pfaceid);

          hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
          clib_memcpy (&ip_face->local_addr, local_addr, sizeof (ip4_address_t));
          clib_memcpy (&ip_face->remote_addr, remote_addr,
                       sizeof (ip4_address_t));
          face->shared.sw_if = sw_if;
          face->shared.flags = flags;
          face->shared.adj = adj;

          dpo_proto = DPO_PROTO_IP4;

          mhash_set_mem (&hicn_face_ip_local_hashtb, &key, (uword *) in_faces, 0);

          /* If the face is an application producer face, we set it as the preferred incoming face. */
          /* This is required to handle the CS separation, and the push api in a lightway*/
          if (is_app_prod)
            {
              in_faces->face_id = *pfaceid;
            }
        }
    }
  else
    {
      face =
	hicn_face_ip6_get (&(remote_addr->ip6), sw_if,
			   &hicn_face_ip_remote_hashtb);

      /* If remote matches the face is a iface */
      if (face == NULL)
	{
	  hicn_iface_ip_add (local_addr, remote_addr, sw_if, pfaceid);
	  face = hicn_dpoi_get_from_idx (*pfaceid);
	}
      else
	{
	  *pfaceid = hicn_dpoi_get_index (face);
	}

      if (!(face->shared.flags & HICN_FACE_FLAGS_IFACE))
        return HICN_ERROR_FACE_ALREADY_CREATED;

      hicn_face_ip_key_t key;
      hicn_face_ip6_get_key (&(local_addr->ip6), sw_if, &key);

      hicn_face_ip_input_faces_t * in_faces =
	hicn_face_ip6_get_vec (&(local_addr->ip6), sw_if,
                               &hicn_face_ip_local_hashtb);

      if (in_faces == NULL)
        {
          adj_index_t adj;
          int ret = hicn_face_ip_find_adj(remote_addr, sw_if, &adj);
          if (ret != HICN_ERROR_NONE)
            return ret;

          hicn_face_ip_input_faces_t in_faces_temp;
          hicn_face_ip_vec_t *vec;
          pool_get(hicn_vec_pool, vec);
          vec_alloc(*vec, 1);
          u32 index = vec - hicn_vec_pool;
          in_faces_temp.vec_id = index;
          vec_add1(*vec, *pfaceid);

          hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
          clib_memcpy (&ip_face->local_addr, local_addr, sizeof (ip6_address_t));
          clib_memcpy (&ip_face->remote_addr, remote_addr,
                       sizeof (ip6_address_t));
          face->shared.sw_if = sw_if;
          face->shared.flags = flags;
          face->shared.adj = adj;

          dpo_proto = DPO_PROTO_IP6;

          in_faces_temp.face_id = *pfaceid;

          mhash_set_mem (&hicn_face_ip_local_hashtb, &key, (uword *) &in_faces_temp, 0);
        }
      else
        {
          hicn_face_ip_vec_t *vec = pool_elt_at_index(hicn_vec_pool, in_faces->vec_id);

          /* */
          if (vec_search(*vec, *pfaceid) != ~0)
            return HICN_ERROR_FACE_ALREADY_CREATED;

          adj_index_t adj;
          int ret = hicn_face_ip_find_adj(remote_addr, sw_if, &adj);
          if (ret != HICN_ERROR_NONE)
            return ret;

          vec_add1(*vec, *pfaceid);

          hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
          clib_memcpy (&ip_face->local_addr, local_addr, sizeof (ip6_address_t));
          clib_memcpy (&ip_face->remote_addr, remote_addr,
                       sizeof (ip6_address_t));
          face->shared.sw_if = sw_if;
          face->shared.flags = flags;
          face->shared.adj = adj;

          dpo_proto = DPO_PROTO_IP6;

          mhash_set_mem (&hicn_face_ip_local_hashtb, &key, (uword *) in_faces, 0);

          /* If the face is an application producer face, we set it as the preferred incoming face. */
          /* This is required to handle the CS separation, and the push api in a lightway*/
          if (is_app_prod)
            {
              in_faces->face_id = *pfaceid;
            }
        }
    }

  retx_t *retx = vlib_process_signal_event_data (vlib_get_main (),
						 hicn_mapme_eventmgr_process_node.
						 index,
						 HICN_MAPME_EVENT_FACE_ADD, 1,
						 sizeof (retx_t));

  /* *INDENT-OFF* */
  *retx = (retx_t)
  {
    .prefix = 0,
    .dpo = (dpo_id_t)
    {
      .dpoi_type = hicn_face_ip_type,
      .dpoi_proto = dpo_proto,
      .dpoi_next_node = 0,
      .dpoi_index = *pfaceid,
    }
  };
  /* *INDENT-ON* */

  return HICN_ERROR_NONE;
}

u8 *
format_hicn_face_ip (u8 * s, va_list * args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);
  hicn_face_t *face;
  hicn_face_ip_t *ip_face;
  ip_adjacency_t *adj;
  vnet_main_t *vnm = vnet_get_main ();

  face = hicn_dpoi_get_from_idx (index);
  ip_face = (hicn_face_ip_t *) face->data;

  if (face->shared.flags & HICN_FACE_FLAGS_FACE)
    {
      ASSERT (face->shared.adj != (adj_index_t) ~ 0);
      adj = adj_get (face->shared.adj);

      hicn_face_id_t face_id = hicn_dpoi_get_index (face);
      s = format (s, "%U Face %d: ", format_white_space, indent, face_id);
      s = format (s, "type IP local %U ",
		  format_ip46_address, &ip_face->local_addr, IP46_TYPE_ANY);
      s =
	format (s, "remote %U ", format_ip46_address, &ip_face->remote_addr,
		IP46_TYPE_ANY);
      s = format (s, "%U", format_vnet_link, adj->ia_link);

      vnet_sw_interface_t *sw_int =
	vnet_get_sw_interface_or_null (vnm, face->shared.sw_if);
      if (sw_int != NULL)
	s = format (s, " dev %U", format_vnet_sw_interface_name, vnm, sw_int);


      if ((face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD))
	s = format (s, " %U", format_hicn_face_prod, face_id, 0);
      else if ((face->shared.flags & HICN_FACE_FLAGS_APPFACE_CONS))
	s = format (s, " %U", format_hicn_face_cons, face_id, 0);

      if ((face->shared.flags & HICN_FACE_FLAGS_DELETED))
	s = format (s, " (deleted)");
    }
  else
    {
      hicn_face_id_t face_id = hicn_dpoi_get_index (face);
      s = format (s, "%U iFace %d: ", format_white_space, indent, face_id);
      s = format (s, "type IP local %U remote %U",
		  format_ip46_address, &ip_face->local_addr, IP46_TYPE_ANY,
		  format_ip46_address, &ip_face->remote_addr, IP46_TYPE_ANY);

      vnet_sw_interface_t *sw_int =
	vnet_get_sw_interface_or_null (vnm, face->shared.sw_if);
      if (sw_int != NULL)
	s = format (s, " dev %U", format_vnet_sw_interface_name, vnm, sw_int);

      if ((face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD))
	s = format (s, " %U", format_hicn_face_prod, face_id, 0);
      else if ((face->shared.flags & HICN_FACE_FLAGS_APPFACE_CONS))
	s = format (s, " %U", format_hicn_face_cons, face_id, 0);

      if ((face->shared.flags & HICN_FACE_FLAGS_DELETED))
	s = format (s, " (deleted)");
    }

  return s;
}

void
hicn_face_ip_get_dpo (hicn_face_t * face, dpo_id_t * dpo)
{

  hicn_face_ip_t *face_ip = (hicn_face_ip_t *) face->data;
  return hicn_dpo_ip_create_from_face (face, dpo,
				       ip46_address_is_ip4
				       (&face_ip->remote_addr) ?
				       strategy_face_ip4_vlib_edge :
				       strategy_face_ip6_vlib_edge);
}

hicn_face_vft_t ip_vft = {
  .format_face = format_hicn_face_ip,
  .hicn_face_del = hicn_face_ip_del,
  .hicn_face_get_dpo = hicn_face_ip_get_dpo,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
