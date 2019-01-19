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

#include "dpo_udp.h"

#include <vnet/ip/format.h>
#include <vnet/adj/adj.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>

const static char *const hicn_face_ip4udp_nodes[] = {
  "hicn-face-encap-udp4",
  "hicn-face-decap-udp4",
  "hicn-iface-decap-udp4",
  "hicn-iface-encap-udp4",
  NULL,
};

const static char *const hicn_face_ip6udp_nodes[] = {
  "hicn-face-encap-udp6",
  "hicn-face-decap-udp6",
  "hicn-iface-decap-udp6",
  "hicn-iface-encap-udp6",
  NULL,
};

const static char *const *const hicn_ipudp_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = hicn_face_ip4udp_nodes,
  [DPO_PROTO_IP6] = hicn_face_ip6udp_nodes
};


const static dpo_vft_t hicn_dpoi_udp_vft = {
  .dv_lock = hicn_face_lock,
  .dv_unlock = hicn_face_unlock,
  .dv_format = format_hicn_face_udp,
};

/* Must be executed after all the strategy nodes are created */
void
hicn_dpo_udp_module_init (void)
{
  mhash_init (&hicn_face_udp_hashtb, sizeof (hicn_face_id_t) /* value */ ,
	      sizeof (hicn_face_udp_key_t) /* key */ );

  /*
   * How much useful is the following registration?
   * So far it seems that we need it only for setting the dpo_type.
   */
  hicn_face_udp_type =
    dpo_register_new_type (&hicn_dpoi_udp_vft, hicn_ipudp_nodes);
}


/* Here udp ports are in host order, move them to network order to do the lookup */
int
hicn_dpo_udp4_create (dpo_id_t * dpo,
		      const ip4_address_t * src_ip,
		      const ip4_address_t * dst_ip,
		      u16 src_port, u16 dst_port,
		      u32 sw_if,
		      adj_index_t ip_adj,
		      u32 node_index,
		      hicn_face_flags_t flags, hicn_face_id_t * face_id)
{
  u16 net_src_port = clib_host_to_net_u16 (src_port);
  u16 net_dst_port = clib_host_to_net_u16 (dst_port);
  hicn_face_t *face = hicn_face_udp4_get (src_ip, dst_ip, src_port, dst_port);

  u8 hicnb_flags;
  /* ip_csum_t sum0; */

  if (face != NULL)
    return HICN_ERROR_FACE_ALREADY_CREATED;

  hicn_dpo_udp4_add_and_lock (dpo, src_ip, dst_ip, net_src_port, net_dst_port,
			      node_index, &hicnb_flags);

  face = hicn_dpoi_get_from_idx (dpo->dpoi_index);

  hicn_face_udp_t *udp_face = (hicn_face_udp_t *) face->data;

  udp_face->hdrs.ip4.ip.checksum =
    ip4_header_checksum (&(udp_face->hdrs.ip4.ip));

  face->shared.flags = flags;
  face->shared.adj = ip_adj;
  face->shared.sw_if = sw_if;
  *face_id = hicn_dpoi_get_index (face);

  return HICN_ERROR_NONE;
}


int
hicn_dpo_udp6_create (dpo_id_t * dpo,
		      const ip6_address_t * src_ip,
		      const ip6_address_t * dst_ip,
		      u16 src_port, u16 dst_port,
		      u32 sw_if,
		      adj_index_t ip_adj,
		      u32 node_index,
		      hicn_face_flags_t flags, hicn_face_id_t * face_id)
{
  u16 net_src_port = clib_host_to_net_u16 (src_port);
  u16 net_dst_port = clib_host_to_net_u16 (dst_port);
  hicn_face_t *face =
    hicn_face_udp6_get (src_ip, dst_ip, net_src_port, net_dst_port);
  u8 hicnb_flags;

  if (face != NULL)
    return HICN_ERROR_FACE_ALREADY_CREATED;

  hicn_dpo_udp6_add_and_lock (dpo, src_ip, dst_ip, net_src_port, net_dst_port,
			      node_index, &hicnb_flags);

  face = hicn_dpoi_get_from_idx (dpo->dpoi_index);

  face->shared.flags = flags;
  face->shared.adj = ip_adj;
  face->shared.sw_if = sw_if;
  *face_id = hicn_dpoi_get_index (face);

  return HICN_ERROR_NONE;
}

void
hicn_dpo_udp_create_from_face (hicn_face_t * face, dpo_id_t * dpo,
			       u16 dpoi_next_node)
{
  hicn_face_id_t face_dpoi_id = hicn_dpoi_get_index (face);
  hicn_face_udp_t *face_udp = (hicn_face_udp_t *) face->data;
  u8 version =
    (face_udp->hdrs.ip4.ip.ip_version_and_header_length & 0xf0) >> 4;
  dpo_set (dpo, face->shared.face_type,
	   version == 4 ? DPO_PROTO_IP4 : DPO_PROTO_IP6, face_dpoi_id);
  dpo->dpoi_next_node = dpoi_next_node;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
