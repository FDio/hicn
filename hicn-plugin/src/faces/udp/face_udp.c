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

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include "face_udp.h"
#include "face_udp_node.h"
#include "dpo_udp.h"
#include "../face.h"
#include "../../strategy.h"
#include "../../strategy_dpo_manager.h"
#include "../../hicn.h"

#include "../../mapme.h"	// HICN_MAPME_EVENT_*
#include "../../mapme_eventmgr.h"	// hicn_mapme_eventmgr_process_node
extern vlib_node_registration_t hicn_mapme_eventmgr_process_node;

mhash_t hicn_face_udp_hashtb;

dpo_type_t hicn_face_udp_type;

ip4_header_t ip4_header_skl = {
  .ip_version_and_header_length = 0x45,
  .tos = 0x00,
  .length = (u16) 0,
  .fragment_id = (u16) 0,
  .flags_and_fragment_offset = (u16) 0,
  .ttl = 254,
  .protocol = IP_PROTOCOL_UDP,
  .checksum = 0,
  .src_address = {{0}},
  .dst_address = {{0}},
};

ip6_header_t ip6_header_skl = {
#if CLIB_ARCH_IS_BIG_ENDIAN
  .ip_version_traffic_class_and_flow_label = 0x60000000,
#else
  .ip_version_traffic_class_and_flow_label = 0x00000060,
#endif
  .payload_length = (u16) 0,
  .protocol = IP_PROTOCOL_UDP,
  .hop_limit = 254,
  .src_address = {{0}},
  .dst_address = {{0}}
};

u32 strategy_face_udp4_vlib_edge;
u32 strategy_face_udp6_vlib_edge;

/* Separated from the hicn_face_udp_init because it cannot be called by the
   init macro due to dependencies with other modules not yet initialied */
void
hicn_face_udp_init_internal ()
{
  ip4_header_t *ip4_hdr = &ip4_header_skl;
  ip4_header_skl.checksum = ip4_header_checksum (ip4_hdr);
}

void
hicn_face_udp_init (vlib_main_t * vm)
{
  int strategy_nodes_n = hicn_strategy_get_all_available ();

  /* Default Strategy has index 0 and it always exists */
  strategy_face_udp4_vlib_edge = vlib_node_add_next (vm,
						     hicn_dpo_get_strategy_vft
						     (default_dpo.
						      hicn_dpo_get_type ())->
						     get_strategy_node_index
						     (),
						     hicn_face_udp4_output_node.
						     index);
  strategy_face_udp6_vlib_edge =
    vlib_node_add_next (vm,
			hicn_dpo_get_strategy_vft (default_dpo.
						   hicn_dpo_get_type ())->
			get_strategy_node_index (),
			hicn_face_udp6_output_node.index);

  /*
   * Create and edge between al the other strategy nodes
   * and the udp_output nodes.
   */
  for (int i = 1; i < strategy_nodes_n; i++)
    {
      u32 temp_index4 = vlib_node_add_next (vm,
					    hicn_dpo_get_strategy_vft_from_id
					    (i)->get_strategy_node_index (),
					    hicn_face_udp4_output_node.index);
      u32 temp_index6 = vlib_node_add_next (vm,
					    hicn_dpo_get_strategy_vft_from_id
					    (i)->get_strategy_node_index (),
					    hicn_face_udp6_output_node.index);
      ASSERT (temp_index4 == strategy_face_udp4_vlib_edge);
      ASSERT (temp_index6 == strategy_face_udp6_vlib_edge);
    }

  hicn_dpo_udp_module_init ();

  register_face_type (hicn_face_udp_type, &udp_vft, "udp");;
}

int
hicn_face_udp_add (const ip46_address_t * local_addr,
		   const ip46_address_t * remote_addr, u16 local_port,
		   u16 remote_port, u32 swif, hicn_face_id_t * pfaceid)
{
  fib_protocol_t fib_type;
  vnet_link_t link_type;
  adj_index_t ip_adj;
  int ret = HICN_ERROR_NONE;
  dpo_proto_t dpo_proto;

  hicn_face_flags_t flags = (hicn_face_flags_t) 0;
  flags |= HICN_FACE_FLAGS_FACE;


  if (ip46_address_is_ip4 (local_addr) && ip46_address_is_ip4 (remote_addr))
    {
      link_type = VNET_LINK_IP4;
      fib_type = FIB_PROTOCOL_IP4;
      ip_adj = adj_nbr_add_or_lock (fib_type, link_type, remote_addr, swif);

      hicn_face_t *face =
	hicn_face_udp4_get (&local_addr->ip4, &remote_addr->ip4, local_port,
			    remote_port);

      if (face != NULL)
	return HICN_ERROR_FACE_ALREADY_CREATED;

      pool_get (hicn_dpoi_face_pool, face);

      hicn_face_udp_t *udp_face = (hicn_face_udp_t *) face->data;

      clib_memcpy (&(udp_face->hdrs.ip4.ip), &ip4_header_skl,
		   sizeof (ip4_header_t));
      clib_memcpy (&(udp_face->hdrs.ip4.ip.src_address), &(local_addr->ip4),
		   sizeof (ip4_address_t));
      clib_memcpy (&(udp_face->hdrs.ip4.ip.dst_address), &(remote_addr->ip4),
		   sizeof (ip4_address_t));

      udp_face->hdrs.ip4.udp.src_port = local_port;
      udp_face->hdrs.ip4.udp.dst_port = remote_port;

      ip_csum_t csum = udp_face->hdrs.ip4.ip.checksum;
      csum = ip_csum_sub_even (csum, ip4_header_skl.src_address.as_u32);
      csum = ip_csum_sub_even (csum, ip4_header_skl.dst_address.as_u32);
      csum =
	ip_csum_add_even (csum, udp_face->hdrs.ip4.ip.src_address.as_u32);
      csum =
	ip_csum_add_even (csum, udp_face->hdrs.ip4.ip.dst_address.as_u32);
      udp_face->hdrs.ip4.ip.checksum = ip_csum_fold (csum);

      face->shared.adj = ip_adj;
      face->shared.sw_if = swif;
      face->shared.pl_id = (u16) 0;
      face->shared.face_type = hicn_face_udp_type;
      face->shared.flags = flags;
      face->shared.locks = 0;

      hicn_face_udp_key_t key;
      hicn_face_udp4_get_key (&local_addr->ip4, &remote_addr->ip4, local_port,
			      remote_port, &key);
      hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);

      mhash_set_mem (&hicn_face_udp_hashtb, &key, (uword *) & dpoi_index, 0);

      *pfaceid = hicn_dpoi_get_index (face);
      dpo_proto = DPO_PROTO_IP4;
    }
  else if (!ip46_address_is_ip4 (local_addr)
	   && !ip46_address_is_ip4 (remote_addr))
    {
      link_type = VNET_LINK_IP6;
      fib_type = FIB_PROTOCOL_IP6;
      ip_adj = adj_nbr_add_or_lock (fib_type, link_type, remote_addr, swif);

      hicn_face_t *face =
	hicn_face_udp6_get (&local_addr->ip6, &remote_addr->ip6, local_port,
			    remote_port);

      if (face != NULL)
	return HICN_ERROR_FACE_ALREADY_CREATED;

      pool_get (hicn_dpoi_face_pool, face);

      hicn_face_udp_t *udp_face = (hicn_face_udp_t *) face->data;

      clib_memcpy (&(udp_face->hdrs.ip6.ip), &ip6_header_skl,
		   sizeof (ip6_header_t));
      clib_memcpy (&(udp_face->hdrs.ip6.ip.src_address), local_addr,
		   sizeof (ip6_address_t));
      clib_memcpy (&(udp_face->hdrs.ip6.ip.dst_address), remote_addr,
		   sizeof (ip6_address_t));

      udp_face->hdrs.ip6.udp.src_port = local_port;
      udp_face->hdrs.ip6.udp.dst_port = remote_port;

      face->shared.adj = ip_adj;
      face->shared.sw_if = swif;
      face->shared.pl_id = (u16) 0;
      face->shared.face_type = hicn_face_udp_type;
      face->shared.flags = flags;
      face->shared.locks = 0;

      hicn_face_udp_key_t key;
      hicn_face_udp6_get_key (&local_addr->ip6, &remote_addr->ip6, local_port,
			      remote_port, &key);
      hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);

      mhash_set_mem (&hicn_face_udp_hashtb, &key, (uword *) & dpoi_index, 0);

      *pfaceid = hicn_dpoi_get_index (face);
      dpo_proto = DPO_PROTO_IP6;
    }
  else
    {
      return HICN_ERROR_IPS_ADDR_TYPE_NONUNIFORM;
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
    .dpoi_type = hicn_face_udp_type,.dpoi_proto =
	dpo_proto,.dpoi_next_node = 0,.dpoi_index = *pfaceid,}
  };

  return ret;
}

int
hicn_face_udp_del (u32 faceid)
{
  return hicn_face_del (faceid);
}

u8 *
format_hicn_face_udp (u8 * s, va_list * args)
{
  hicn_face_id_t face_id = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);
  hicn_face_t *face;
  hicn_face_udp_t *udp_face;
  ip_adjacency_t *adj;
  u8 ipv = 0x40;
  vnet_main_t *vnm = vnet_get_main ();


  face = hicn_dpoi_get_from_idx (face_id);
  udp_face = (hicn_face_udp_t *) (face->data);

  if (face->shared.flags & HICN_FACE_FLAGS_FACE)
    {
      ASSERT (face->shared.adj != (adj_index_t) ~ 0);
      adj = adj_get (face->shared.adj);

      s = format (s, "%U Face %d: ", format_white_space, indent, face_id);
      if (udp_face->hdrs.ip4.ip.ip_version_and_header_length == ipv)
	{
	  s = format (s, "type UDP local %U|%u ",
		      format_ip4_address, &udp_face->hdrs.ip4.ip.src_address,
		      clib_net_to_host_u16 (udp_face->hdrs.ip4.udp.src_port));
	  s =
	    format (s, "remote %U|%u ", format_ip4_address,
		    &udp_face->hdrs.ip4.ip.dst_address,
		    clib_net_to_host_u16 (udp_face->hdrs.ip4.udp.dst_port));
	  s = format (s, "%U", format_vnet_link, adj->ia_link);
	  s = format (s, " dev %U", format_vnet_sw_interface_name, vnm,
		      vnet_get_sw_interface (vnm, face->shared.sw_if));
	  if ((face->shared.flags & HICN_FACE_FLAGS_DELETED))
	    s = format (s, " (deleted)");
	}
      else
	{
	  s = format (s, "type UDP local %U|%u ",
		      format_ip6_address, &udp_face->hdrs.ip6.ip.src_address,
		      clib_net_to_host_u16 (udp_face->hdrs.ip6.udp.src_port));
	  s =
	    format (s, "remote %U|%u", format_ip6_address,
		    &udp_face->hdrs.ip6.ip.dst_address,
		    clib_net_to_host_u16 (udp_face->hdrs.ip6.udp.dst_port));
	  s = format (s, "%U", format_vnet_link, adj->ia_link);
	  s = format (s, " dev %U", format_vnet_sw_interface_name, vnm,
		      vnet_get_sw_interface (vnm, face->shared.sw_if));
	  if ((face->shared.flags & HICN_FACE_FLAGS_DELETED))
	    s = format (s, " (deleted)");
	}
    }
  else
    {
      s = format (s, "IFace %d: ", format_white_space, indent, face_id);
      if (udp_face->hdrs.ip4.ip.ip_version_and_header_length == ipv)
	{
	  s = format (s, "type UDP local %U|%u",
		      format_ip4_address, &udp_face->hdrs.ip4.ip.src_address,
		      clib_net_to_host_u16 (udp_face->hdrs.ip4.udp.src_port));
	  s =
	    format (s, " local %U|%u", format_ip4_address,
		    &udp_face->hdrs.ip4.ip.dst_address,
		    clib_net_to_host_u16 (udp_face->hdrs.ip4.udp.dst_port));
	  s =
	    format (s, " dev %U", format_vnet_sw_interface_name, vnm,
		    vnet_get_sw_interface (vnm, face->shared.sw_if));
	  if ((face->shared.flags & HICN_FACE_FLAGS_DELETED))
	    s = format (s, " (deleted)");
	}
      else
	{
	  s = format (s, "type UDP local %U|%u",
		      format_ip6_address, &udp_face->hdrs.ip6.ip.src_address,
		      clib_net_to_host_u16 (udp_face->hdrs.ip6.udp.src_port));
	  s =
	    format (s, " remote %U|%u", format_ip6_address,
		    &udp_face->hdrs.ip6.ip.dst_address,
		    clib_net_to_host_u16 (udp_face->hdrs.ip6.udp.dst_port));
	  s =
	    format (s, " dev %U", format_vnet_sw_interface_name, vnm,
		    vnet_get_sw_interface (vnm, face->shared.sw_if));
	  if ((face->shared.flags & HICN_FACE_FLAGS_DELETED))
	    s = format (s, " (deleted)");
	}
    }

  return s;
}

void
hicn_face_udp_get_dpo (hicn_face_t * face, dpo_id_t * dpo)
{
  hicn_face_udp_t *face_udp = (hicn_face_udp_t *) face->data;
  u8 version =
    (face_udp->hdrs.ip4.ip.ip_version_and_header_length & 0xf0) >> 4;
  return hicn_dpo_udp_create_from_face (face, dpo,
					version ==
					(u8) 4 ? strategy_face_udp4_vlib_edge
					: strategy_face_udp6_vlib_edge);
}

hicn_face_vft_t udp_vft = {
  .format_face = format_hicn_face_udp,
  .hicn_face_del = hicn_face_udp_del,
  .hicn_face_get_dpo = hicn_face_udp_get_dpo,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
