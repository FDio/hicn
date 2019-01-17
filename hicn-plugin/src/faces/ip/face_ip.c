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
						    hicn_dpo_get_strategy_vft
						    (default_dpo.
						     hicn_dpo_get_type ())->
						    get_strategy_node_index
						    (),
						    hicn_face_ip4_output_node.
						    index);

  strategy_face_ip6_vlib_edge = vlib_node_add_next (vm,
						    hicn_dpo_get_strategy_vft
						    (default_dpo.
						     hicn_dpo_get_type ())->
						    get_strategy_node_index
						    (),
						    hicn_face_ip6_output_node.
						    index);
  /*
   * Create and edge between al the other strategy nodes
   * and the ip_encap nodes.
   */
  for (int i = 1; i < strategy_nodes_n; i++)
    {
      u32 temp_index4 = vlib_node_add_next (vm,
					    hicn_dpo_get_strategy_vft_from_id
					    (i)->get_strategy_node_index (),
					    hicn_face_ip4_output_node.index);
      u32 temp_index6 = vlib_node_add_next (vm,
					    hicn_dpo_get_strategy_vft_from_id
					    (i)->get_strategy_node_index (),
					    hicn_face_ip6_output_node.index);
      ASSERT (temp_index4 == strategy_face_ip4_vlib_edge);
      ASSERT (temp_index6 == strategy_face_ip6_vlib_edge);
    }

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

  if (ip46_address_is_ip4 (&face_ip->local_addr))
    {
      hicn_face_ip4_get_key (&(face_ip->local_addr.ip4), face->shared.sw_if,
			     &key);
      mhash_unset (&hicn_face_ip_local_hashtb, &key, (uword *) & old_key);
      hicn_face_ip4_get_key (&(face_ip->remote_addr.ip4), face->shared.sw_if,
			     &key);
      mhash_unset (&hicn_face_ip_remote_hashtb, &key, (uword *) & old_key);
    }
  else
    {
      hicn_face_ip6_get_key (&(face_ip->local_addr.ip6), face->shared.sw_if,
			     &key);
      mhash_unset (&hicn_face_ip_local_hashtb, &key, (uword *) & old_key);
      hicn_face_ip6_get_key (&(face_ip->remote_addr.ip6), face->shared.sw_if,
			     &key);
      mhash_unset (&hicn_face_ip_remote_hashtb, &key, (uword *) & old_key);
    }
  return hicn_face_del (face_id);
}


/*
 * Utility that adds a new face cache entry. For the moment we assume that the
 * ip_adjacency has already been set up.
 */
int
hicn_face_ip_add (const ip46_address_t * local_addr,
		  const ip46_address_t * remote_addr,
		  int sw_if, hicn_face_id_t * pfaceid)
{
  fib_protocol_t fib_type;
  vnet_link_t link_type;
  adj_index_t adj;
  dpo_proto_t dpo_proto;

  /* Check if we found at least one ip address */
  if (ip46_address_is_zero (local_addr) || ip46_address_is_zero (remote_addr))
    return HICN_ERROR_FACE_NO_GLOBAL_IP;

  if (ip46_address_is_ip4 (local_addr) && ip46_address_is_ip4 (remote_addr))
    {
      link_type = VNET_LINK_IP4;
      fib_type = FIB_PROTOCOL_IP4;
    }
  else
    {
      link_type = VNET_LINK_IP6;
      fib_type = FIB_PROTOCOL_IP6;
    }


  adj = adj_nbr_add_or_lock (fib_type, link_type, remote_addr, sw_if);

  hicn_face_flags_t flags = (hicn_face_flags_t) 0;
  flags |= HICN_FACE_FLAGS_FACE;

  hicn_face_t *face;
  if (ip46_address_is_ip4 (local_addr))
    {
      face =
	hicn_face_ip4_get (&(local_addr->ip4), sw_if,
			   &hicn_face_ip_local_hashtb);

      if (face != NULL)
	return HICN_ERROR_FACE_ALREADY_CREATED;

      face =
	hicn_face_ip4_get (&(remote_addr->ip4), sw_if,
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

      hicn_face_ip_key_t key;
      hicn_face_ip4_get_key (&(local_addr->ip4), sw_if, &key);

      mhash_set_mem (&hicn_face_ip_local_hashtb, &key, (uword *) pfaceid, 0);

      hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
      clib_memcpy (&ip_face->local_addr, local_addr, sizeof (ip4_address_t));
      clib_memcpy (&ip_face->remote_addr, remote_addr,
		   sizeof (ip4_address_t));
      face->shared.sw_if = sw_if;
      face->shared.flags = flags;
      face->shared.adj = adj;

      dpo_proto = DPO_PROTO_IP4;
    }
  else
    {
      face =
	hicn_face_ip6_get (&(local_addr->ip6), sw_if,
			   &hicn_face_ip_local_hashtb);

      if (face != NULL)
	return HICN_ERROR_FACE_ALREADY_CREATED;

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

      hicn_face_ip_key_t key;
      hicn_face_ip6_get_key (&(local_addr->ip6), sw_if, &key);

      mhash_set_mem (&hicn_face_ip_local_hashtb, &key, (uword *) pfaceid, 0);

      hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
      clib_memcpy (&ip_face->local_addr, local_addr, sizeof (ip6_address_t));
      clib_memcpy (&ip_face->remote_addr, remote_addr,
		   sizeof (ip6_address_t));
      face->shared.sw_if = sw_if;
      face->shared.flags = flags;
      face->shared.adj = adj;

      dpo_proto = DPO_PROTO_IP6;
    }

  retx_t *retx = vlib_process_signal_event_data (vlib_get_main (),
						 hicn_mapme_eventmgr_process_node.
						 index,
						 HICN_MAPME_EVENT_FACE_ADD, 1,
						 sizeof (retx_t));
  *retx = (retx_t)
  {
    .prefix = 0,.dpo = (dpo_id_t)
    {
    .dpoi_type = hicn_face_ip_type,.dpoi_proto = dpo_proto,.dpoi_next_node =
	0,.dpoi_index = *pfaceid,}
  };

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
      s = format (s, " dev %U", format_vnet_sw_interface_name, vnm,
		  vnet_get_sw_interface (vnm, face->shared.sw_if));

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
      s =
	format (s, " dev %U", format_vnet_sw_interface_name, vnm,
		vnet_get_sw_interface (vnm, face->shared.sw_if));

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
				       ip46_address_is_ip4 (&face_ip->
							    remote_addr) ?
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
