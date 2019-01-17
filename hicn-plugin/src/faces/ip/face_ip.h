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

#ifndef __HICN_FACE_IP_H__
#define __HICN_FACE_IP_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include "../face.h"
#include "../../cache_policies/cs_policy.h"

/**
 * @file
 *
 * @brief IP face
 *
 * A face is carried through nodes as a dpo. The face state is the object
 * pointed by the dpoi_index in the dpo_id_t (see
 * https://docs.fd.io/vpp/18.07/d0/d37/dpo_8h_source.html)
 */
typedef struct hicn_ip_face_t_
{
  /**
   * The headers to paint, in packet painting order
   */
  /* Local address of the interface sw_if */
  ip46_address_t local_addr;

  /* Remote address of neighbor */
  ip46_address_t remote_addr;

} hicn_face_ip_t;


/**
 * Hash tables that indexes a face by local address. For fast lookup when an
 * data arrives.
 */
extern mhash_t hicn_face_ip_local_hashtb;

/**
 * Hash tables that indexes a face by remote address. For fast lookup when an
 * interest arrives.
 */
extern mhash_t hicn_face_ip_remote_hashtb;

/**
 * Key definition for the mhash table. An ip face is uniquely identified by ip
 * address and the interface id. The ip address can correspond to the remote ip
 * address of the next hicn hop, or to the local address of the receiving
 * interface. The former is used to retrieve the incoming face when an interest
 * is received, the latter when the arring packet is a data.
 */
typedef struct hicn_face_ip_key_s
{
  ip46_address_t addr;
  u32 sw_if;
} hicn_face_ip_key_t;


extern hicn_face_type_t hicn_face_ip_type;
extern hicn_face_vft_t ip_vft;

/**
 * @brief Create the key object for the mhash. Fill in the key object with the
 * expected values.
 *
 * @param addr Local or remote ip v6 address of the face
 * @param sw_if interface associated to the face
 * @param key Pointer to an allocated hicn_face_ip_key_t object
 */
always_inline void
hicn_face_ip6_get_key (const ip6_address_t * addr,
		       u32 sw_if, hicn_face_ip_key_t * key)
{
  key->addr.ip6 = *addr;
  key->sw_if = sw_if;
}


/**
 * @brief Create the key object for the mhash. Fill in the key object with the
 * expected values.
 *
 * @param addr Local or remote ip v4 address of the face
 * @param sw_if interface associated to the face
 * @param key Pointer to an allocated hicn_face_ip_key_t object
 */
always_inline void
hicn_face_ip4_get_key (const ip4_address_t * addr,
		       u32 sw_if, hicn_face_ip_key_t * key)
{
  ip46_address_set_ip4 (&(key->addr), addr);
  key->sw_if = sw_if;
}

/**
 * @brief Get the dpoi from the ip v4 address. Does not add any lock.
 *
 * @param addr Ip v4 address used to create the key for the hash table.
 * @param sw_if Software interface id used to create the key for the hash table.
 * @param hashtb Hash table (remote or local) where to perform the lookup.
 *
 * @result Pointer to the face.
 */
always_inline hicn_face_t *
hicn_face_ip4_get (const ip4_address_t * addr, u32 sw_if, mhash_t * hashtb)
{
  hicn_face_ip_key_t key;

  hicn_face_ip4_get_key (addr, sw_if, &key);

  hicn_face_id_t *dpoi_index = (hicn_face_id_t *) mhash_get (hashtb,
							     &key);

  return dpoi_index == NULL ? NULL : hicn_dpoi_get_from_idx (*dpoi_index);
}

/**
 * @brief Get the dpoi from the ip v6 address. Does not add any lock.
 *
 * @param addr Ip v6 address used to create the key for the hash table.
 * @param sw_if Software interface id used to create the key for the hash table.
 * @param hashtb Hash table (remote or local) where to perform the lookup.
 *
 * @result Pointer to the face.
 */
always_inline hicn_face_t *
hicn_face_ip6_get (const ip6_address_t * addr, u32 sw_if, mhash_t * hashtb)
{
  hicn_face_ip_key_t key;

  hicn_face_ip6_get_key (addr, sw_if, &key);

  hicn_face_id_t *dpoi_index = (hicn_face_id_t *) mhash_get (hashtb,
							     &key);

  return dpoi_index == NULL ? NULL : hicn_dpoi_get_from_idx (*dpoi_index);
}

/**
 * @brief Create a new face ip. API for other modules (e.g., routing)
 *
 * @param local_addr Local ip v4 or v6 address of the face
 * @param remote_addr Remote ip v4 or v6 address of the face
 * @param sw_if interface associated to the face
 * @param is_app_face Boolean to set the face as an application face
 * @param pfaceid Pointer to return the face id
 * @return HICN_ERROR_FACE_NO_GLOBAL_IP if the face does not have a globally
 * reachable ip address, otherwise HICN_ERROR_NONE
 */
int hicn_face_ip_add (const ip46_address_t * local_addr,
		      const ip46_address_t * remote_addr,
		      int swif, hicn_face_id_t * pfaceid);

/**
 * @brief Create a new incomplete face ip. (Meant to be used by the data plane)
 *
 * @param local_addr Local ip v4 or v6 address of the face
 * @param remote_addr Remote ip v4 or v6 address of the face
 * @param sw_if interface associated to the face
 * @param pfaceid Pointer to return the face id
 * @return HICN_ERROR_FACE_NO_GLOBAL_IP if the face does not have a globally
 * reachable ip address, otherwise HICN_ERROR_NONE
 */
always_inline void
hicn_iface_ip_add (const ip46_address_t * local_addr,
		   const ip46_address_t * remote_addr,
		   int sw_if, hicn_face_id_t * pfaceid)
{
  hicn_face_t *face;
  pool_get (hicn_dpoi_face_pool, face);

  hicn_face_ip_t *ip_face = (hicn_face_ip_t *) (face->data);

  clib_memcpy (&(ip_face->local_addr.ip6), local_addr,
	       sizeof (ip6_address_t));
  clib_memcpy (&(ip_face->remote_addr.ip6), remote_addr,
	       sizeof (ip6_address_t));
  face->shared.sw_if = sw_if;

  face->shared.adj = ADJ_INDEX_INVALID;
  face->shared.pl_id = (u16) 0;
  face->shared.face_type = hicn_face_ip_type;
  face->shared.flags = HICN_FACE_FLAGS_IFACE;
  face->shared.locks = 0;

  hicn_face_ip_key_t key;
  hicn_face_ip6_get_key (&(remote_addr->ip6), sw_if, &key);
  *pfaceid = hicn_dpoi_get_index (face);

  mhash_set_mem (&hicn_face_ip_remote_hashtb, &key, (uword *) pfaceid, 0);
}

/**
 * @brief Delete an ip face
 *
 * @param face_id Id of the face to delete
 * @return HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise
 * HICN_ERROR_NONE
 */
int hicn_face_ip_del (hicn_face_id_t face_id);

/**
 * @brief Format a IP face
 *
 * @param s Pointer to a previous string. If null it will be initialize
 * @param args Array storing input values. Expected u32 face_id and u32 indent
 * @return String with the formatted face
 */
u8 *format_hicn_face_ip (u8 * s, va_list * args);

/**
 * @brief Create a dpo from an ip face
 *
 * @param face Face from which to create the dpo
 * @return the dpo
 */
void hicn_face_ip_get_dpo (hicn_face_t * face, dpo_id_t * dpo);

#endif // __HICN_FACE_IP_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
