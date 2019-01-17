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

#ifndef __HICN_DPO_IP_H__
#define __HICN_DPO_IP_H__

#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>

#include "face_ip.h"
#include "../face.h"

/**
 * @brief Initialize the internal structures of the dpo ip face module.
 */
void hicn_dpo_ip_module_init (void);


/**
 * @brief Retrieve a face from the ip4 local address and returns its dpo. This
 * method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup. If the face doesn't exist dpo = NULL
 * @param is_appface: Boolean that indicates whether the face is an application
 * face or not
 * @param local_addr: Ip v4 local address of the face
 * @param sw_if: software interface id of the face
 *
 * @result HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise HICN_ERROR_NONE.
 */
always_inline int
hicn_dpo_ip4_lock_from_local (dpo_id_t * dpo,
			      u8 * is_appface,
			      const ip4_address_t * local_addr, u32 sw_if)
{
  hicn_face_t *face =
    hicn_face_ip4_get (local_addr, sw_if, &hicn_face_ip_local_hashtb);

  if (PREDICT_FALSE (face == NULL))
    return HICN_ERROR_FACE_NOT_FOUND;

  *is_appface = face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD;

  hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);
  dpo_set (dpo, hicn_face_ip_type, DPO_PROTO_IP4, dpoi_index);
  dpo->dpoi_next_node = ~0;
  dpo_lock (dpo);

  return HICN_ERROR_NONE;
}

/**
 * @brief Retrieve a face from the ip6 local address and returns its dpo. This
 * method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup. If the face doesn't exist dpo = NULL
 * @param is_appface: Boolean that indicates whether the face is an application
 * face or not
 * @param local_addr: Ip v6 local address of the face
 * @param sw_if: software interface id of the face
 *
 * @result HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise HICN_ERROR_NONE.
 */
always_inline int
hicn_dpo_ip6_lock_from_local (dpo_id_t * dpo,
			      u8 * is_appface,
			      const ip6_address_t * local_addr, u32 sw_if)
{
  hicn_face_t *face =
    hicn_face_ip6_get (local_addr, sw_if, &hicn_face_ip_local_hashtb);

  if (PREDICT_FALSE (face == NULL))
    return HICN_ERROR_FACE_NOT_FOUND;

  *is_appface = face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD;

  hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);
  dpo_set (dpo, hicn_face_ip_type, DPO_PROTO_IP6, dpoi_index);
  dpo->dpoi_next_node = ~0;
  dpo_lock (dpo);

  return HICN_ERROR_NONE;
}


/**
 * @brief Retrieve, or create if it doesn't exist, a face from the ip6 local
 * address and returns its dpo. This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup
 * @param is_appface: Boolean that indicates whether the face is an application
 * face or not
 * @param local_addr: Ip v4 local address of the face
 * @param remote_addr: Ip v4 remote address of the face
 * @param sw_if: software interface id of the face
 * @param node_index: vlib edge index to use in the packet processing
 */
always_inline void
hicn_dpo_ip4_add_and_lock_from_remote (dpo_id_t * dpo,
				       u8 * is_appface,
				       const ip4_address_t * local_addr,
				       const ip4_address_t * remote_addr,
				       u32 sw_if, u32 node_index)
{
  /*All (complete) faces are indexed by remote addess as well */
  hicn_face_t *face =
    hicn_face_ip4_get (remote_addr, sw_if, &hicn_face_ip_remote_hashtb);

  if (face == NULL)
    {
      hicn_face_id_t dpoi_index;
      ip46_address_t local_addr46 = to_ip46 (0, (u8 *) local_addr);
      ip46_address_t remote_addr46 = to_ip46 (0, (u8 *) remote_addr);
      hicn_iface_ip_add (&local_addr46, &remote_addr46, sw_if, &dpoi_index);

      *is_appface = 0;

      dpo_set (dpo, hicn_face_ip_type, DPO_PROTO_IP4, dpoi_index);
      dpo->dpoi_next_node = node_index;
      dpo_lock (dpo);

      return;
    }

  /* Code replicated on purpose */
  *is_appface = face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD;

  hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);
  dpo_set (dpo, hicn_face_ip_type, DPO_PROTO_IP4, dpoi_index);
  dpo->dpoi_next_node = node_index;
  dpo_lock (dpo);
}

/**
 * @brief Retrieve, or create if it doesn't exist, a face from the ip6 local
 * address and returns its dpo. This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup
 * @param is_appface: Boolean that indicates whether the face is an application
 * face or not
 * @param local_addr: Ip v6 local address of the face
 * @param remote_addr: Ip v6 remote address of the face
 * @param sw_if: software interface id of the face
 * @param node_index: vlib edge index to use in the packet processing
 */
always_inline void
hicn_dpo_ip6_add_and_lock_from_remote (dpo_id_t * dpo,
				       u8 * is_appface,
				       const ip6_address_t * local_addr,
				       const ip6_address_t * remote_addr,
				       u32 sw_if, u32 node_index)
{
  /*All (complete) faces are indexed by remote addess as well */
  hicn_face_t *face =
    hicn_face_ip6_get (remote_addr, sw_if, &hicn_face_ip_remote_hashtb);

  if (face == NULL)
    {
      hicn_face_id_t dpoi_index;
      hicn_iface_ip_add ((ip46_address_t *) local_addr,
			 (ip46_address_t *) remote_addr, sw_if, &dpoi_index);

      *is_appface = 0;

      dpo_set (dpo, hicn_face_ip_type, DPO_PROTO_IP4, dpoi_index);
      dpo->dpoi_next_node = node_index;
      dpo_lock (dpo);

      return;
    }
  /* Code replicated on purpose */
  *is_appface = face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD;

  index_t dpoi_index = hicn_dpoi_get_index (face);
  dpo_set (dpo, hicn_face_ip_type, DPO_PROTO_IP6, dpoi_index);
  dpo->dpoi_next_node = node_index;
  dpo_lock (dpo);
}


/**
 * @brief Create an ip face and its corresponding dpo. Meant to be used for the
 * control plane.
 *
 * @param dpo: Data plane object that point to the face created.
 * @param local_addr: Ip v4 local address of the face
 * @param remote_addr: Ip v4 remote address of the face
 * @param sw_if: software interface id of the face
 * @param adj: Ip adjacency corresponding to the remote address in the face
 * @param node_index: vlib edge index to use in the packet processing
 * @param flags: Flags of the face
 * @param face_id: Identifier for the face (dpoi_index)
 * @return HICN_ERROR_FACE_ALREADY_CREATED if the face exists, otherwise HICN_ERROR_NONE
 */
int hicn_dpo_ip4_create (dpo_id_t * dpo,
			 const ip4_address_t * local_addr,
			 const ip4_address_t * remote_addr,
			 u32 sw_if,
			 adj_index_t adj,
			 u32 node_index,
			 hicn_face_flags_t flags, hicn_face_id_t * face_id);

/**
 * @brief Create an ip face and its corresponding dpo. Meant to be used for the
 * control plane.
 *
 * @param dpo: Data plane object that point to the face created.
 * @param local_addr: Ip v6 local address of the face
 * @param remote_addr: Ip v6 remote address of the face
 * @param sw_if: software interface id of the face
 * @param adj: Ip adjacency corresponding to the remote address in the face
 * @param node_index: vlib edge index to use in the packet processing
 * @param flags: Flags of the face
 * @param face_id: Identifier for the face (dpoi_index)
 * @return HICN_ERROR_FACE_ALREADY_CREATED if the face exists, otherwise HICN_ERROR_NONE
 */
int hicn_dpo_ip6_create (dpo_id_t * dpo,
			 const ip6_address_t * local_addr,
			 const ip6_address_t * remote_addr,
			 u32 sw_if,
			 adj_index_t adj,
			 u32 node_index,
			 hicn_face_flags_t flags, hicn_face_id_t * face_id);

/**
 * @brief Create a dpo from an ip face
 *
 * @param face Face from which to create the dpo
 * @param dpoi_next_node Edge index that connects a node to the iface or face nodes
 * @return the dpo
 */
void hicn_dpo_ip_create_from_face (hicn_face_t * face, dpo_id_t * dpo,
				   u16 dpoi_next_node);

#endif // __HICN_DPO_IP_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
