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

#ifndef __HICN_DPO_UDP_H__
#define __HICN_DPO_UDP_H__

#include <vnet/adj/adj_types.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

#include "face_udp.h"
#include "../face.h"
#include "../../error.h"


/**
 * @brief Initialize the internal structures of the dpo udp face module.
 */
void hicn_dpo_udp_module_init (void);

/**
 * @brief Create a udp face and its corresponding dpo. Meant to be used for the
 * control plane.
 *
 * @param dpo: Data plane object that point to the face created.
 * @param local_addr: Local address of the UDP tunnel
 * @param remote_addr: Remote address of the UDP tunnel
 * @param local_port: Local port of the UDP tunnel
 * @param remote_port: Remote port of the UDP tunnel
 * @param adj: Ip adjacency corresponding to the remote address in the face
 * @param node_index: vlib edge index to use in the packet processing
 * @param flags: Flags of the face
 * @param face_id: Identifier for the face (dpoi_index)
 * @return HICN_ERROR_FACE_ALREADY_CREATED if the face exists, otherwise HICN_ERROR_NONE
 */
int
hicn_dpo_udp4_create (dpo_id_t * dpo,
		      const ip4_address_t * local_addr,
		      const ip4_address_t * remote_addr,
		      u16 local_port, u16 remote_port,
		      u32 sw_if,
		      adj_index_t adj,
		      u32 node_index,
		      hicn_face_flags_t flags, hicn_face_id_t * face_id);

/**
 * @brief Retrieve a face using the face identifier, i.e., the  quadruplet (local_addr, remote_addr,
 * local_port, remote_port). This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup. If the face doesn't exist dpo = NULL
 * @param local_addr: Local address of the UDP tunnel
 * @param remote_addr: Remote address of the UDP tunnel
 * @param local_port: Local port of the UDP tunnel
 * @param remote_port: Remote port of the UDP tunnel
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not in the hicn_buffer. (Currently only IP faces can be appface)
 *
 * @result HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise HICN_ERROR_NONE.
 */
always_inline int
hicn_dpo_udp4_lock (dpo_id_t * dpo,
		    const ip4_address_t * local_addr,
		    const ip4_address_t * remote_addr,
		    u16 local_port, u16 remote_port, u8 * hicnb_flags)
{
  dpo->dpoi_type = DPO_FIRST;
  dpo->dpoi_proto = DPO_PROTO_NONE;
  dpo->dpoi_index = INDEX_INVALID;
  dpo->dpoi_next_node = 0;

  hicn_face_t *face =
    hicn_face_udp4_get (local_addr, remote_addr, local_port, remote_port);

  if (PREDICT_FALSE (face == NULL))
    return HICN_ERROR_FACE_NOT_FOUND;

  index_t dpoi_index = hicn_dpoi_get_index (face);
  dpo_set (dpo, hicn_face_udp_type, DPO_PROTO_IP4, dpoi_index);
  dpo->dpoi_next_node = ~0;
  dpo_lock (dpo);

  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;

  return HICN_ERROR_NONE;
}

/**
 * @brief Retrieve, or create if it doesn't exist, a face from the face
 * identifier (local_addr, remote_addr, local_port, remote_port) and returns its
 * dpo. This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup
 * @param local_addr: Local address of the UDP tunnel
 * @param remote_addr: Remote address of the UDP tunnel
 * @param local_port: Local port of the UDP tunnel
 * @param remote_port: Remote port of the UDP tunnel
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not. (Currently only IP faces can be appface)
 * @param node_index: vlib edge index to use in the packet processing
 */
always_inline void
hicn_dpo_udp4_add_and_lock (dpo_id_t * dpo,
			    const ip4_address_t * local_addr,
			    const ip4_address_t * remote_addr,
			    u16 local_port, u16 remote_port,
			    u32 node_index, u8 * hicnb_flags)
{
  dpo->dpoi_type = DPO_FIRST;
  dpo->dpoi_proto = DPO_PROTO_NONE;
  dpo->dpoi_index = INDEX_INVALID;
  dpo->dpoi_next_node = 0;

  hicn_face_t *face =
    hicn_face_udp4_get (local_addr, remote_addr, local_port, remote_port);

  if (face == NULL)
    {
      pool_get (hicn_dpoi_face_pool, face);

      hicn_face_udp_t *udp_face = (hicn_face_udp_t *) face->data;

      clib_memcpy (&(udp_face->hdrs.ip4.ip), &ip4_header_skl,
		   sizeof (ip4_header_t));
      clib_memcpy (&(udp_face->hdrs.ip4.ip.src_address), local_addr,
		   sizeof (ip4_address_t));
      clib_memcpy (&(udp_face->hdrs.ip4.ip.dst_address), remote_addr,
		   sizeof (ip4_address_t));

      udp_face->hdrs.ip4.udp.src_port = local_port;
      udp_face->hdrs.ip4.udp.dst_port = remote_port;

      face->shared.adj = ADJ_INDEX_INVALID;
      face->shared.pl_id = (u16) 0;
      face->shared.face_type = hicn_face_udp_type;
      face->shared.flags = HICN_FACE_FLAGS_IFACE;
      face->shared.locks = 0;

      hicn_face_udp_key_t key;
      hicn_face_udp4_get_key (local_addr, remote_addr, local_port,
			      remote_port, &key);
      hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);

      mhash_set_mem (&hicn_face_udp_hashtb, &key, (uword *) & dpoi_index, 0);
      face = face;

      *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
      dpo_set (dpo, hicn_face_udp_type, DPO_PROTO_IP4, dpoi_index);
      dpo->dpoi_next_node = node_index;
      dpo_lock (dpo);

      return;
    }

  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;

  hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);
  dpo_set (dpo, hicn_face_udp_type, DPO_PROTO_IP4, dpoi_index);
  dpo->dpoi_next_node = node_index;
  dpo_lock (dpo);
}

/**
 * @brief Create a udp face and its corresponding dpo. Meant to be used for the
 * control plane.
 *
 * @param dpo: Data plane object that point to the face created.
 * @param local_addr: Local address of the UDP tunnel
 * @param remote_addr: Remote address of the UDP tunnel
 * @param local_port: Local port of the UDP tunnel
 * @param remote_port: Remote port of the UDP tunnel
 * @param adj: Ip adjacency corresponding to the remote address in the face
 * @param node_index: vlib edge index to use in the packet processing
 * @param flags: Flags of the face
 * @param face_id: Identifier for the face (dpoi_index)
 * @return HICN_ERROR_FACE_ALREADY_CREATED if the face exists, otherwise HICN_ERROR_NONE
 */
int
hicn_dpo_udp6_create (dpo_id_t * dpo,
		      const ip6_address_t * local_addr,
		      const ip6_address_t * remote_addr,
		      u16 local_port, u16 remote_port,
		      u32 sw_if,
		      adj_index_t adj,
		      u32 node_index,
		      hicn_face_flags_t flags, hicn_face_id_t * face_id);


/**
 * @brief Retrieve a face using the face identifier, i.e., the  quadruplet (local_addr, remote_addr,
 * local_port, remote_port). This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup. If the face doesn't exist dpo = NULL
 * @param local_addr: Local address of the UDP tunnel
 * @param remote_addr: Remote address of the UDP tunnel
 * @param local_port: Local port of the UDP tunnel
 * @param remote_port: Remote port of the UDP tunnel
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not. (Currently only IP faces can be appface)
 *
 * @result HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise HICN_ERROR_NONE.
 */
always_inline int
hicn_dpo_udp6_lock (dpo_id_t * dpo,
		    const ip6_address_t * local_addr,
		    const ip6_address_t * remote_addr,
		    u16 local_port, u16 remote_port, u8 * hicnb_flags)
{
  dpo->dpoi_type = DPO_FIRST;
  dpo->dpoi_proto = DPO_PROTO_NONE;
  dpo->dpoi_index = INDEX_INVALID;
  dpo->dpoi_next_node = 0;

  hicn_face_t *face =
    hicn_face_udp6_get (local_addr, remote_addr, local_port, remote_port);


  if (PREDICT_FALSE (face == NULL))
    return HICN_ERROR_FACE_NOT_FOUND;

  hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);
  dpo_set (dpo, hicn_face_udp_type, DPO_PROTO_IP4, dpoi_index);
  dpo->dpoi_next_node = ~0;
  dpo_lock (dpo);
  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;

  return HICN_ERROR_NONE;
}

/**
 * @brief Retrieve, or create if it doesn't exist, a face from the face
 * identifier (local_addr, remote_addr, local_port, remote_port) and returns its
 * dpo. This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup
 * @param local_addr: Local address of the UDP tunnel
 * @param remote_addr: Remote address of the UDP tunnel
 * @param local_port: Local port of the UDP tunnel
 * @param remote_port: Remote port of the UDP tunnel
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not. (Currently only IP faces can be appface)
 * @param node_index: vlib edge index to use in the packet processing
 */
always_inline void
hicn_dpo_udp6_add_and_lock (dpo_id_t * dpo,
			    const ip6_address_t * local_addr,
			    const ip6_address_t * remote_addr,
			    u16 local_port, u16 remote_port,
			    u32 node_index, u8 * hicnb_flags)
{
  dpo->dpoi_type = DPO_FIRST;
  dpo->dpoi_proto = DPO_PROTO_NONE;
  dpo->dpoi_index = INDEX_INVALID;
  dpo->dpoi_next_node = 0;

  hicn_face_t *face =
    hicn_face_udp6_get (local_addr, remote_addr, local_port, remote_port);

  if (face == NULL)
    {
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

      face->shared.adj = ADJ_INDEX_INVALID;
      face->shared.pl_id = (u16) 0;
      face->shared.face_type = hicn_face_udp_type;
      face->shared.flags = HICN_FACE_FLAGS_IFACE;
      face->shared.locks = 0;

      hicn_face_udp_key_t key;
      hicn_face_udp6_get_key (local_addr, remote_addr, local_port,
			      remote_port, &key);
      hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);

      mhash_set_mem (&hicn_face_udp_hashtb, &key, (uword *) & dpoi_index, 0);

      *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
      dpo_set (dpo, hicn_face_udp_type, DPO_PROTO_IP6, dpoi_index);
      dpo->dpoi_next_node = node_index;
      dpo_lock (dpo);

      return;
    }

  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;

  hicn_face_id_t dpoi_index = hicn_dpoi_get_index (face);
  dpo_set (dpo, hicn_face_udp_type, DPO_PROTO_IP6, dpoi_index);
  dpo->dpoi_next_node = node_index;
  dpo_lock (dpo);
}

/**
 * @brief Create a dpo from a udp face
 *
 * @param face Face from which to create the dpo
 * @return the dpo
 */
void hicn_dpo_udp_create_from_face (hicn_face_t * face, dpo_id_t * dpo,
				    u16 dpoi_next_node);

#endif // __HICN_DPO_UDP_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
