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

#ifndef __HICN_FACE_UDP_H__
#define __HICN_FACE_UDP_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>

#include "../face.h"

/**
 * @file
 * @brief UDP face
 *
 * This file containes the definition of UDP faces.
 * UDP faces encap and decap an hicn packet into a UDP tunnel.
 * Src and dst address in interest and data packets are not considered and
 * should be set to 0 (not checked in the forwarder).
 */

/* Pre-instantiated ip header to fast fill an newly encapsulated packet */
extern ip4_header_t ip4_header_skl;
extern ip6_header_t ip6_header_skl;

#define INVALID_UDP_DPO_INDEX ~0

/**
 * @brief UDP face representation. The following is stored in the data field of
 * an hicn_face_t object (see hicn_face.h). A UDP face is identifies by the
 * quadruplet (src addr, dst addr, src port, dst port).
 */
typedef struct hicn_face_udp_t_
{
  /**
   * The headers to paint, in packet painting order
   */
  union
  {
    struct
    {
      ip4_header_t ip;
      udp_header_t udp;
    } __attribute__ ((packed)) ip4;
    struct
    {
      ip6_header_t ip;
      udp_header_t udp;
    } __attribute__ ((packed)) ip6;
  } __attribute__ ((packed)) hdrs;
} hicn_face_udp_t;

/* Hast table mapping the udp key with the face id (dpoi_index pointing to and
   element in the face pool defined in hicn_face.h)*/
extern mhash_t hicn_face_udp_hashtb;

/**
 * @brief Hash table key.
 */
typedef struct hicn_face_udp_key_s
{
  ip46_address_t local_addr;
  ip46_address_t remote_addr;
  u16 local_port;
  u16 remote_port;
} hicn_face_udp_key_t;

/* DPO type for the udp face */
extern dpo_type_t hicn_face_udp_type;

/* VFT table for the udp face. Mainly used to format the face in the right way */
extern hicn_face_vft_t udp_vft;

/**
 * @brief Create the key object for the mhash. Fill in the key object with the
 * expected values.
 *
 * @param local_addr Local address of the UDP tunnel
 * @param remote_addr Remote address of the UDP tunnel
 * @param local_port Local port of the UDP tunnel
 * @param remote_port Remote port of the UDP tunnel
 * @param key Pointer to an allocated hicn_face_udp_key_t object
 */
always_inline void
hicn_face_udp4_get_key (const ip4_address_t * local_addr,
			const ip4_address_t * remote_addr,
			u16 local_port, u16 remote_port,
			hicn_face_udp_key_t * key)
{

  ip46_address_set_ip4 (&(key->local_addr), local_addr);
  ip46_address_set_ip4 (&(key->remote_addr), remote_addr);
  key->local_port = local_port;
  key->remote_port = remote_port;
}

/**
 * @brief Create the key object for the mhash. Fill in the key object with the
 * expected values.
 *
 * @param local_addr Local address of the UDP tunnel
 * @param remote_addr Remote address of the UDP tunnel
 * @param local_port Local port of the UDP tunnel
 * @param remote_port Remote port of the UDP tunnel
 * @param key Pointer to an allocated hicn_face_udp_key_t object
 */
always_inline void
hicn_face_udp6_get_key (const ip6_address_t * local_addr,
			const ip6_address_t * remote_addr,
			u16 local_port, u16 remote_port,
			hicn_face_udp_key_t * key)
{
  key->local_addr.ip6 = *local_addr;
  key->remote_addr.ip6 = *remote_addr;
  key->local_port = local_port;
  key->remote_port = remote_port;
}

/**
 * @brief Get the dpoi from the quadruplet that identifies the face. Does not add any lock.
 *
 * @param local_addr Local address of the UDP tunnel
 * @param remote_addr Remote address of the UDP tunnel
 * @param local_port Local port of the UDP tunnel
 * @param remote_port Remote port of the UDP tunnel
 *
 * @result Pointer to the face.
 */
always_inline hicn_face_t *
hicn_face_udp4_get (const ip4_address_t * local_addr,
		    const ip4_address_t * remote_addr,
		    u16 local_port, u16 remote_port)
{
  hicn_face_udp_key_t key;

  hicn_face_udp4_get_key (local_addr, remote_addr, local_port, remote_port,
			  &key);

  hicn_face_id_t *dpoi_index =
    (hicn_face_id_t *) mhash_get (&hicn_face_udp_hashtb,
				  &key);

  return dpoi_index == NULL ? NULL : hicn_dpoi_get_from_idx (*dpoi_index);
}

/**
 * @brief Get the dpoi from the quadruplet that identifies the face. Does not add any lock.
 *
 * @param local_addr Local address of the UDP tunnel (network order)
 * @param remote_addr Remote address of the UDP tunnel (network order)
 * @param local_port Local port of the UDP tunnel (network order)
 * @param remote_port Remote port of the UDP tunnel (network order)
 *
 * @result Pointer to the face.
 */
always_inline hicn_face_t *
hicn_face_udp6_get (const ip6_address_t * local_addr,
		    const ip6_address_t * remote_addr,
		    u16 local_port, u16 remote_port)
{
  hicn_face_udp_key_t key;

  hicn_face_udp6_get_key (local_addr, remote_addr, local_port, remote_port,
			  &key);

  hicn_face_id_t *dpoi_index =
    (hicn_face_id_t *) mhash_get (&hicn_face_udp_hashtb,
				  &key);

  return dpoi_index == NULL ? NULL : hicn_dpoi_get_from_idx (*dpoi_index);
}


/**
 * @brief Initialize the udp face module
 */
void hicn_face_udp_init (vlib_main_t * vm);

/**
 * @brief Create a new face ip. API for other modules (e.g., routing)
 *
 * @param local_addr Local ip v4 or v6 address of the face (network order)
 * @param remote_addr Remote ip v4 or v6 address of the face (network order)
 * @param local_port Local udp port of the face (network order)
 * @param remote_port Remote udp port of the face (network order)
 * @param sw_if interface associated to the face
 * @param pfaceid Pointer to return the face id
 * @return HICN_ERROR_FACE_NO_GLOBAL_IP if the face does not have a globally
 * reachable ip address, otherwise HICN_ERROR_NONE
 */
int hicn_face_udp_add (const ip46_address_t * local_addr,
		       const ip46_address_t * remote_addr, u16 local_port,
		       u16 remote_port, u32 swif, hicn_face_id_t * pfaceid);

/**
 * @brief Delete an ip face
 *
 * @param face_id Id of the face to delete
 * @return HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise
 * HICN_ERROR_NONE
 */
int hicn_face_udp_del (hicn_face_id_t faceid);

/**
 * @brief Format a UDP face
 *
 * @param s Pointer to a previous string. If null it will be initialize
 * @param args Array storing input values. Expected u32 indent and u32 face_id
 * @return String with the formatted face
 */
u8 *format_hicn_face_udp (u8 * s, va_list * args);

/**
 * @brief Create a dpo from a udp face
 *
 * @param face Face from which to create the dpo
 * @return the dpo
 */
void hicn_face_udp_get_dpo (hicn_face_t * face, dpo_id_t * dpo);

/**
 * @brief Init some internal structures
 */
void hicn_face_udp_init_internal (void);

#endif // __HICN_FACE_UDP_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
