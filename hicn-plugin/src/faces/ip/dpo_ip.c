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

hicn_face_ip_vec_t * hicn_vec_pool;

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
	      sizeof (hicn_face_ip_input_faces_t) /* value */ ,
	      sizeof (hicn_face_ip_key_t) /* key */ );
  mhash_init (&hicn_face_ip_remote_hashtb,
	      sizeof (hicn_face_id_t) /* value */ ,
	      sizeof (hicn_face_ip_key_t) /* key */ );

  pool_alloc(hicn_vec_pool, 100);

  /*
   * How much useful is the following registration?
   * So far it seems that we need it only for setting the dpo_type.
   */
  hicn_face_ip_type =
    dpo_register_new_type (&hicn_face_ip_vft, hicn_ip_nodes);
}

void
hicn_dpo_ip_create_from_face (hicn_face_t * face, dpo_id_t * dpo,
			      u16 dpoi_next_node)
{
  hicn_face_id_t face_dpoi_id = hicn_dpoi_get_index (face);
  hicn_face_ip_t *ip_face = (hicn_face_ip_t *) face->data;
  dpo_set (dpo, face->shared.face_type,
	   ip46_address_is_ip4 (&ip_face->local_addr) ? DPO_PROTO_IP4 :
	   DPO_PROTO_IP6, face_dpoi_id);
  dpo->dpoi_next_node = dpoi_next_node;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
