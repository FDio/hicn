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

#include "dpo_ip.h"

mhash_t hicn_face_ip_local_hashtb;
mhash_t hicn_face_ip_remote_hashtb;
dpo_type_t hicn_face_ip_type;

const static char *const hicn_face_ip4dpoi_nodes[] = {
  "hicn-face-ip4-input",
  "hicn-face-ip4-output",
  "hicn-iface-ip4-input",
  "hicn-iface-ip4-output",
  NULL,
};

const static char *const hicn_face_ip6dpoi_nodes[] = {
  "hicn-face-ip6-input",
  "hicn-face-ip6-output",
  "hicn-iface-ip6-input",
  "hicn-iface-ip6-output",
  NULL,
};

const static char *const *const hicn_ip_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = hicn_face_ip4dpoi_nodes,
  [DPO_PROTO_IP6] = hicn_face_ip6dpoi_nodes
};

const static dpo_vft_t hicn_face_ip_vft = {
  .dv_lock = hicn_face_lock,
  .dv_unlock = hicn_face_unlock,
  .dv_format = format_hicn_face_ip,
};

/* Must be executed after all the strategy nodes are created */
void
hicn_dpo_ip_module_init (void)
{
  mhash_init (&hicn_face_ip_local_hashtb,
	      sizeof (hicn_face_id_t) /* value */ ,
	      sizeof (hicn_face_ip_key_t) /* key */ );
  mhash_init (&hicn_face_ip_remote_hashtb,
	      sizeof (hicn_face_id_t) /* value */ ,
	      sizeof (hicn_face_ip_key_t) /* key */ );

  /*
   * How much useful is the following registration?
   * So far it seems that we need it only for setting the dpo_type.
   */
  hicn_face_ip_type =
    dpo_register_new_type (&hicn_face_ip_vft, hicn_ip_nodes);
}


int
hicn_dpo_ip4_create (dpo_id_t * dpo,
		     const ip4_address_t * local_addr,
		     const ip4_address_t * remote_addr,
		     u32 sw_if,
		     adj_index_t adj,
		     u32 node_index,
		     hicn_face_flags_t flags, hicn_face_id_t * face_id)
{
  /* If local matches the dpoi is a face */
  hicn_face_t *face =
    hicn_face_ip4_get (local_addr, sw_if, &hicn_face_ip_local_hashtb);
  u8 is_appface;

  if (face != NULL)
    return HICN_ERROR_FACE_ALREADY_CREATED;

  face = hicn_face_ip4_get (remote_addr, sw_if, &hicn_face_ip_remote_hashtb);

  if (face == NULL)
    {
      hicn_dpo_ip4_add_and_lock_from_remote (dpo, &is_appface, local_addr,
					     remote_addr, sw_if, node_index);
      *face_id = (hicn_face_id_t) dpo->dpoi_index;
      face = hicn_dpoi_get_from_idx (*face_id);
    }
  else
    {
      *face_id = hicn_dpoi_get_index (face);
      dpo_set (dpo, hicn_face_ip_type, DPO_PROTO_IP4, *face_id);
      dpo->dpoi_next_node = node_index;
    }


  hicn_face_ip_key_t key;
  hicn_face_ip4_get_key (local_addr, sw_if, &key);

  mhash_set_mem (&hicn_face_ip_local_hashtb, &key, (uword *) face_id, 0);

  hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
  ip46_address_set_ip4 (&ip_face->local_addr, local_addr);
  ip46_address_set_ip4 (&ip_face->remote_addr, remote_addr);
  face->shared.flags = flags;
  face->shared.adj = adj;

  return HICN_ERROR_NONE;
}

int
hicn_dpo_ip6_create (dpo_id_t * dpo,
		     const ip6_address_t * local_addr,
		     const ip6_address_t * remote_addr,
		     u32 sw_if,
		     adj_index_t adj,
		     u32 node_index,
		     hicn_face_flags_t flags, hicn_face_id_t * face_id)
{
  /* If local matches the dpoi is a face */
  hicn_face_t *face =
    hicn_face_ip6_get (local_addr, sw_if, &hicn_face_ip_local_hashtb);

  u8 is_appface;

  if (face != NULL)
    return HICN_ERROR_FACE_ALREADY_CREATED;

  face = hicn_face_ip6_get (remote_addr, sw_if, &hicn_face_ip_remote_hashtb);

  /* If remote matches the dpoi is a iface */
  if (face == NULL)
    {
      hicn_dpo_ip6_add_and_lock_from_remote (dpo, &is_appface, local_addr,
					     remote_addr, sw_if, node_index);
      *face_id = (hicn_face_id_t) dpo->dpoi_index;
      face = hicn_dpoi_get_from_idx (*face_id);
    }
  else
    {
      *face_id = hicn_dpoi_get_index (face);
      dpo_set (dpo, hicn_face_ip_type, DPO_PROTO_IP6, *face_id);
      dpo->dpoi_next_node = node_index;
    }

  hicn_face_ip_key_t key;
  hicn_face_ip6_get_key (local_addr, sw_if, &key);

  mhash_set_mem (&hicn_face_ip_local_hashtb, &key, (uword *) face_id, 0);

  hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
  clib_memcpy (&ip_face->local_addr, local_addr, sizeof (ip6_address_t));
  clib_memcpy (&ip_face->remote_addr, remote_addr, sizeof (ip6_address_t));
  face->shared.sw_if = sw_if;
  face->shared.flags = flags;
  face->shared.adj = adj;


  return HICN_ERROR_NONE;
}

void
hicn_dpo_ip_create_from_face (hicn_face_t * face, dpo_id_t * dpo,
			      u16 dpoi_next_node)
{
  hicn_face_id_t face_dpoi_id = hicn_dpoi_get_index (face);
  hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
  dpo_set (dpo, face->shared.face_type,
	   ip46_address_is_ip4 (&ip_face->
				local_addr) ? DPO_PROTO_IP4 : DPO_PROTO_IP6,
	   face_dpoi_id);
  dpo->dpoi_next_node = dpoi_next_node;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
