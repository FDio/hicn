/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef __HICN_FACE_H__
#define __HICN_FACE_H__

#include <vnet/fib/fib_node.h>
#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vppinfra/bihash_8_8.h>
#include <vnet/adj/adj_midchain.h>

#include <vpp_plugins/hicn/error.h>

#include "../udp_tunnels/udp_tunnel.h"
#include "../hicn_logging.h"

typedef u8 hicn_face_flags_t;
typedef index_t hicn_face_id_t;

/**
 * @file face.h
 *
 * This file implements a general face type. The purpose of a face is to
 * carry the needed information to forward interest and data packets to the
 * next node in the network. There are two type of faces: complete faces (in
 * short faces), and incomplete faces (in short ifaces).
 *
 * A face that does not contain the indication of the adjacency is an
 * incomplete face (iface), otherwise it is considered to be complete. Ifaces
 * are used to forward data back to the previous hICN hop from which we
 * received an interest, while faces are used to forward interest packets to
 * the next hicn node. Faces and ifaces are created at two different points in
 * time. Faces are created when a route is added, while ifaces are created when
 * an interest is received. In details, faces and ifaces carry the following
 * information:
 * - nat_addr: the ip address to perform src nat or dst nat on interest and
 * data packets, respectively;
 * - pl_id: the path label
 * - locks: the number of entities using this face. When 0 the face can be
 * deallocated
 * - dpo: the dpo that identifies the next node in the vlib graph for
 * processing the vlib buffer. The dpo contains the dpo.dpoi_next field that
 * points to the next node in the vlib graph and the dpo.dpoi_index which is an
 * index to adj used by the next node to perform the l2 rewrite. In case of
 * ifaces, it is likely we don't know the adjacency when creting the face. In
 * this case, the next node in the vlib graph will be the node that performs a
 * lookup in the fib. Only in case of udp tunnels, which are bidirectional
 * tunnel we know that the incoming tunnel is also the outgoing one, therefore
 * in this case we store the tunnel in the dpo.dpoi_index fields. For all the
 * other tunnels (which are most likely unidirectional), the source address of
 *   the interest will be used to retrieve the outgoing tunnel when sending the
 * corresponding data back.
 * - sw_if: the incoming interface of the interest
 * - fib_node, fib_entry_index and fib_sibling are information used to be
 * notified of changes in the adjacency pointed by the dpo.
 *
 * We maintain one hash tables to retrieve faces and ifaces, which indexes
 * faces and ifaces for nat_address, sw_if and dpo.
 */

/**
 * @brief Structure representing a face. It containes the fields shared among
 * all the types of faces as well it leaves some space for storing additional
 * information specific to each type.
 */
typedef struct __attribute__ ((packed)) hicn_face_s
{
  /* Flags to idenfity if the face is incomplete (iface), complete (face) */
  /* And a network or application face (1B) */
  hicn_face_flags_t flags;

  /* Align the upcoming fields */
  u8 align;

  /* Path label (2B) */
  u16 pl_id;

  /* Number of dpo holding a reference to the dpoi (4B) */
  u32 locks;

  /* Dpo for the adjacency (8B) */
  union
  {
    dpo_id_t dpo;
    u64 align_dpo;
  };

  /* Local address of the interface sw_if */
  ip46_address_t nat_addr;

  /* local interface for the local ip address */
  u32 sw_if;

  fib_node_t fib_node;

  fib_node_index_t fib_entry_index;

  u32 fib_sibling;
} hicn_face_t;

/* Pool of faces */
extern hicn_face_t *hicn_dpoi_face_pool;

/* Flags */
/* A face is complete and it stores all the information. A iface lacks of the
   adj index, therefore sending a packet through a iface require a lookup in
   the FIB. */
#define HICN_FACE_FLAGS_DEFAULT 0x00
#define HICN_FACE_FLAGS_FACE	0x01
#define HICN_FACE_FLAGS_IFACE	0x02
#define HICN_FACE_FLAGS_APPFACE_PROD                                          \
  0x04 /* Currently only IP face can be appface */
#define HICN_FACE_FLAGS_APPFACE_CONS                                          \
  0x08 /* Currently only IP face can be appface */
#define HICN_FACE_FLAGS_DELETED 0x10
#define HICN_FACE_FLAGS_UDP	0x20

#define HICN_FACE_NULL (hicn_face_id_t) ~0

#define HICN_FACE_FLAGS_APPFACE_PROD_BIT 2
#define HICN_FACE_FLAGS_APPFACE_CONS_BIT 3

#define HICN_BUFFER_FLAGS_DEFAULT	   0x00
#define HICN_BUFFER_FLAGS_NEW_FACE	   0x02
#define HICN_BUFFER_FLAGS_FROM_UDP4_TUNNEL 0x04
#define HICN_BUFFER_FLAGS_FROM_UDP6_TUNNEL 0x08

STATIC_ASSERT ((1 << HICN_FACE_FLAGS_APPFACE_PROD_BIT) ==
		 HICN_FACE_FLAGS_APPFACE_PROD,
	       "HICN_FACE_FLAGS_APPFACE_PROD_BIT and  "
	       "HICN_FACE_FLAGS_APPFACE_PROD must correspond");

STATIC_ASSERT ((1 << HICN_FACE_FLAGS_APPFACE_CONS_BIT) ==
		 HICN_FACE_FLAGS_APPFACE_CONS,
	       "HICN_FACE_FLAGS_APPFACE_CONS_BIT and  "
	       "HICN_FACE_FLAGS_APPFACE_CONS must correspond");

/**
 * @brief Definition of the virtual functin table for an hICN FACE DPO.
 */
typedef struct hicn_face_vft_s
{
  u8 *(*format_face) (u8 *s, va_list *args);
  /**< Format an hICN face dpo*/
  int (*hicn_face_del) (hicn_face_id_t face_id);
  void (*hicn_face_get_dpo) (hicn_face_t *face, dpo_id_t *dpo);
} hicn_face_vft_t;

#define foreach_hicn_face_counter                                             \
  _ (INTEREST_RX, 0, "Interest rx")                                           \
  _ (INTEREST_TX, 1, "Interest tx")                                           \
  _ (DATA_RX, 2, "Data rx")                                                   \
  _ (DATA_TX, 3, "Data tx")

typedef enum
{
#define _(a, b, c) HICN_FACE_COUNTERS_##a = (b),
  foreach_hicn_face_counter
#undef _
    HICN_N_COUNTER
} hicn_face_counters_t;

extern mhash_t hicn_face_hashtb;

extern const char *HICN_FACE_CTRX_STRING[];

#define get_face_counter_string(ctrxno)                                       \
  (char *) (HICN_FACE_CTRX_STRING[ctrxno])

/* Vector maintaining a dpo per face */
extern dpo_id_t *face_dpo_vec;
extern hicn_face_vft_t *face_vft_vec;

/* Vector holding the set of face names */
extern char **face_type_names_vec;

/* Pathlabel counter */
extern u8 pl_index;

/* First face type registered in the sytem.*/
extern dpo_type_t first_type;

/* Per-face counters */
extern vlib_combined_counter_main_t *counters;

/**
 * @brief Return the face id from the face object
 *
 * @param Pointer to the face state
 * @return face id
 */
always_inline hicn_face_id_t
hicn_dpoi_get_index (hicn_face_t *face_dpoi)
{
  return face_dpoi - hicn_dpoi_face_pool;
}

/**
 * @brief Return the face object from the face id.
 * This method is robust to invalid face id.
 *
 * @param dpoi_index Face identifier
 * @return Pointer to the face or NULL
 */
always_inline hicn_face_t *
hicn_dpoi_get_from_idx_safe (hicn_face_id_t dpoi_index)
{
  if (!pool_is_free_index (hicn_dpoi_face_pool, dpoi_index))
    return (hicn_face_t *) pool_elt_at_index (hicn_dpoi_face_pool, dpoi_index);
  else
    return NULL;
}

/**
 * @brief Return the face from the face id. Face id must be valid.
 *
 * @param dpoi_index Face identifier
 * @return Pointer to the face
 */
always_inline hicn_face_t *
hicn_dpoi_get_from_idx (hicn_face_id_t dpoi_index)
{
  return (hicn_face_t *) pool_elt_at_index (hicn_dpoi_face_pool, dpoi_index);
}

/**
 * @brief Return true if the face id belongs to an existing face
 */
always_inline int
hicn_dpoi_idx_is_valid (hicn_face_id_t face_id)
{
  return pool_len (hicn_dpoi_face_pool) > face_id &&
	 !pool_is_free_index (hicn_dpoi_face_pool, face_id);
}

/**
 * @brief Delete a face
 *
 * @param face_id Id of the face to delete
 * @return HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise
 * HICN_ERROR_NONE
 */
int hicn_face_del (hicn_face_id_t face_id);

/**
 * @brief Add a lock to the face dpo
 *
 * @param dpo Pointer to the face dpo
 */
always_inline void
hicn_face_lock_with_id (hicn_face_id_t face_id)
{
  hicn_face_t *face;
  face = hicn_dpoi_get_from_idx (face_id);
  face->locks++;
}

/**
 * @brief Remove a lock to the face dpo. Deallocate the face id locks == 0
 *
 * @param dpo Pointer to the face dpo
 */
always_inline int
hicn_face_unlock_with_id (hicn_face_id_t face_id)
{
  hicn_face_t *face;
  face = hicn_dpoi_get_from_idx (face_id);

  if (face->locks > 0)
    {
      face->locks--;

      if (face->locks == 0)
	{
	  HICN_DEBUG ("Deleting face %d", face_id);
	  return hicn_face_del (face_id);
	}
    }

  return HICN_ERROR_NONE;
}

/**
 * @brief Add a lock to the face through its dpo
 *
 * @param dpo Pointer to the face dpo
 */
always_inline void
hicn_face_lock (dpo_id_t *dpo)
{
  hicn_face_lock_with_id (dpo->dpoi_index);
}

/**
 * @brief Remove a lock to the face through its dpo. Deallocate the face id
 * locks == 0
 *
 * @param dpo Pointer to the face dpo
 */
always_inline void
hicn_face_unlock (dpo_id_t *dpo)
{
  hicn_face_unlock_with_id (dpo->dpoi_index);
}

/**
 * @brief Init the internal structures of the face module
 *
 * Must be called before processing any packet
 */
void hicn_face_module_init (vlib_main_t *vm);

u8 *format_hicn_face (u8 *s, va_list *args);

/**
 * @brief Format all the existing faces
 *
 * @param s Pointer to a previous string. If null it will be initialize
 * @param n Number of input parameters
 * @return String with the faces formatted
 */
u8 *format_hicn_face_all (u8 *s, int n, ...);

/**
 * @bried vector of faces used to collect faces having the same local address
 *
 */
typedef hicn_face_id_t *hicn_face_vec_t;

typedef struct hicn_input_faces_s_
{
  /* Vector of all possible input faces */
  u32 vec_id;

  /* Preferred face. If an prod_app face is in the vector it will be the
   * preferred one. */
  /* It's not possible to have multiple prod_app face in the same vector, they
   * would have */
  /* the same local address. Every prod_app face is a point-to-point face
   * between the forwarder */
  /* and the application. */
  hicn_face_id_t face_id;

} hicn_face_input_faces_t;

/**
 * Key definition for the mhash table. An face is uniquely identified by ip
 * address, the interface id and a dpo pointing to the next node in the vlib
 * graph. The ip address can correspond to the remote ip address of the next
 * hicn hop, or to the local address of the receiving interface. The former is
 * used to retrieve the incoming face when an interest is received, the latter
 * when the arring packet is a data. If the face is a regular face In case of
 * iface, the following structure can be filled in different ways:
 * - dpo equal to DPO_INVALID when the iface is a regular hICN iface
 * - in case of udp_tunnel dpo =
 *   {
 *    .dpoi_index = tunnel_id,
 *    .dpoi_type = DPO_FIRST,  //We don't need the type, we leave it invalid
 *    .dpoi_proto = DPO_PROTO_IP4 or DPO_PROTO_IP6,
 *    .dpoi_next_node = HICN6_IFACE_OUTPUT_NEXT_UDP4_ENCAP or
 *                      HICN6_IFACE_OUTPUT_NEXT_UDP6_ENCAP or
 *                      HICN4_IFACE_OUTPUT_NEXT_UDP4_ENCAP or
 *                      HICN4_IFACE_OUTPUT_NEXT_UDP6_ENCAP
 *    }
 */
typedef struct __attribute__ ((packed)) hicn_face_key_s
{
  ip46_address_t addr;
  union
  {
    dpo_id_t dpo;
    u64 align_dpo;
  };
  u32 sw_if;
} hicn_face_key_t;

/**
 * @brief Create the key object for the mhash. Fill in the key object with the
 * expected values.
 *
 * @param addr nat address of the face
 * @param sw_if interface associated to the face
 * @param key Pointer to an allocated hicn_face_ip_key_t object
 */
always_inline void
hicn_face_get_key (const ip46_address_t *addr, u32 sw_if, const dpo_id_t *dpo,
		   hicn_face_key_t *key)
{
  key->dpo = *dpo;
  key->addr = *addr;
  key->sw_if = sw_if;
}

/**
 * @brief Get the face obj from the nat address. Does not add any lock.
 *
 * @param addr Ip v4 address used to create the key for the hash table.
 * @param sw_if Software interface id used to create the key for the hash
 * table.
 * @param hashtb Hash table (remote or local) where to perform the lookup.
 *
 * @result Pointer to the face.
 */
always_inline hicn_face_t *
hicn_face_get (const ip46_address_t *addr, u32 sw_if, mhash_t *hashtb,
	       index_t adj_index)
{
  hicn_face_key_t key;

  dpo_id_t dpo = DPO_INVALID;

  dpo.dpoi_index = adj_index;

  hicn_face_get_key (addr, sw_if, &dpo, &key);

  hicn_face_id_t *dpoi_index = (hicn_face_id_t *) mhash_get (hashtb, &key);

  if (dpoi_index != NULL && hicn_dpoi_idx_is_valid (*dpoi_index))
    {
      hicn_face_lock_with_id (*dpoi_index);
      return hicn_dpoi_get_from_idx (*dpoi_index);
    }

  return NULL;
}

/**
 * @brief Get the face obj from the nat address and the dpo. Does not add any
 * lock.
 *
 * @param addr Ip v4 address used to create the key for the hash table.
 * @param sw_if Software interface id used to create the key for the hash
 * table.
 * @param hashtb Hash table (remote or local) where to perform the lookup.
 *
 * @result Pointer to the face.
 */
always_inline hicn_face_t *
hicn_face_get_with_dpo (const ip46_address_t *addr, u32 sw_if,
			const dpo_id_t *dpo, mhash_t *hashtb)
{
  hicn_face_key_t key;

  hicn_face_get_key (addr, sw_if, dpo, &key);

  hicn_face_id_t *dpoi_index = (hicn_face_id_t *) mhash_get (hashtb, &key);

  if (dpoi_index != NULL && hicn_dpoi_idx_is_valid (*dpoi_index))
    {
      hicn_face_lock_with_id (*dpoi_index);
      return hicn_dpoi_get_from_idx (*dpoi_index);
    }

  return NULL;
}

/**
 * @brief Create a new face ip. API for other modules (e.g., routing)
 *
 * @param dpo_nh dpo contained in the face that points to the next node in
 *        the vlib graph
 * @param nat_addr nat ip v4 or v6 address of the face
 * @param sw_if interface associated to the face
 * @param pfaceid Pointer to return the face id
 * @param is_app_prod if HICN_FACE_FLAGS_APPFACE_PROD the face is a local
 * application face, all other values are ignored
 * @return HICN_ERROR_FACE_NO_GLOBAL_IP if the face does not have a globally
 * reachable ip address, otherwise HICN_ERROR_NONE
 */
int hicn_face_add (const dpo_id_t *dpo_nh, ip46_address_t *nat_address,
		   int sw_if, hicn_face_id_t *pfaceid, u8 is_app_prod);

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
hicn_iface_add (ip46_address_t *nat_address, int sw_if,
		hicn_face_id_t *pfaceid, u32 adj_index, u8 flags)
{
  hicn_face_t *face;
  pool_get (hicn_dpoi_face_pool, face);

  clib_memcpy (&(face->nat_addr), nat_address, sizeof (ip46_address_t));
  face->sw_if = sw_if;

  face->dpo = (dpo_id_t) DPO_INVALID;
  face->dpo.dpoi_index = adj_index;

  hicn_face_key_t key;
  hicn_face_get_key (nat_address, sw_if, &face->dpo, &key);

  face->dpo.dpoi_next_node = 1;

  face->pl_id = pl_index++;
  face->flags = HICN_FACE_FLAGS_IFACE;
  face->flags |= flags;
  face->locks = 1;

  *pfaceid = hicn_dpoi_get_index (face);

  mhash_set_mem (&hicn_face_hashtb, &key, (uword *) pfaceid, 0);

  for (int i = 0; i < HICN_N_COUNTER; i++)
    {
      vlib_validate_combined_counter (&counters[(*pfaceid) * HICN_N_COUNTER],
				      i);
      vlib_zero_combined_counter (&counters[(*pfaceid) * HICN_N_COUNTER], i);
    }
}

/**** Helpers to manipulate faces and ifaces from the face/iface input nodes
 * ****/

/**
 * @brief Call back to get the adj of the tunnel
 */
static adj_walk_rc_t
hicn4_iface_adj_walk_cb (adj_index_t ai, void *ctx)
{

  hicn_face_t *face = (hicn_face_t *) ctx;

  dpo_set (&face->dpo, DPO_ADJACENCY_MIDCHAIN, DPO_PROTO_IP4, ai);
  adj_nbr_midchain_stack (ai, &face->dpo);

  return (ADJ_WALK_RC_CONTINUE);
}

/**
 * @brief Retrieve, or create if it doesn't exist, a face from the ip6 local
 * address and returns its dpo. This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not
 * @param nat_addr: Ip v4 remote address of the face
 * @param sw_if: software interface id of the face
 * @param node_index: vlib edge index to use in the packet processing
 */
always_inline int
hicn_face_ip4_add_and_lock (hicn_face_id_t *index, u8 *hicnb_flags,
			    const ip4_address_t *nat_addr, u32 sw_if,
			    u32 adj_index, u32 node_index)
{
  int ret = HICN_ERROR_NONE;
  /*All (complete) faces are indexed by remote addess as well */

  ip46_address_t ip_address = { 0 };
  ip46_address_set_ip4 (&ip_address, nat_addr);

  /* if the face exists, it adds a lock */
  hicn_face_t *face =
    hicn_face_get (&ip_address, sw_if, &hicn_face_hashtb, adj_index);

  if (face == NULL)
    {
      hicn_face_id_t idx;
      u8 face_flags = 0;

      hicn_iface_add (&ip_address, sw_if, &idx, adj_index, face_flags);

      face = hicn_dpoi_get_from_idx (idx);

      if (*hicnb_flags & HICN_BUFFER_FLAGS_FROM_UDP6_TUNNEL &&
	  adj_index != ADJ_INDEX_INVALID)
	{
	  face->dpo.dpoi_type = dpo_type_udp_ip6;
	  face->dpo.dpoi_proto = DPO_PROTO_IP6;
	}
      else if (*hicnb_flags & HICN_BUFFER_FLAGS_FROM_UDP4_TUNNEL &&
	       adj_index != ADJ_INDEX_INVALID)
	{
	  face->dpo.dpoi_type = dpo_type_udp_ip4;
	  face->dpo.dpoi_proto = DPO_PROTO_IP4;
	}
      else
	{
	  face->dpo.dpoi_type = DPO_FIRST;
	  face->dpo.dpoi_proto = DPO_PROTO_IP6;
	}

      face->dpo.dpoi_index = adj_index;
      face->dpo.dpoi_next_node = node_index;

      /* if (nat_addr->as_u32 == 0) */
      /*   { */
      adj_nbr_walk (face->sw_if, FIB_PROTOCOL_IP4, hicn4_iface_adj_walk_cb,
		    face);
      /* } */

      *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
      *hicnb_flags |= HICN_BUFFER_FLAGS_NEW_FACE;

      *index = idx;
      return ret;
    }
  else
    {
      /* unlock the face. We don't take a lock on each interest we receive */
      hicn_face_id_t face_id = hicn_dpoi_get_index (face);
      hicn_face_unlock_with_id (face_id);
      ret = HICN_ERROR_FACE_ALREADY_CREATED;
    }

  /* Code replicated on purpose */
  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
  *hicnb_flags |= (face->flags & HICN_FACE_FLAGS_APPFACE_PROD) >>
		  HICN_FACE_FLAGS_APPFACE_PROD_BIT;

  *index = hicn_dpoi_get_index (face);

  return ret;
}

/**
 * @brief Call back to get the adj of the tunnel
 */
static adj_walk_rc_t
hicn6_iface_adj_walk_cb (adj_index_t ai, void *ctx)
{

  hicn_face_t *face = (hicn_face_t *) ctx;

  ip_adjacency_t *adj = adj_get (ai);
  if ((adj->lookup_next_index == IP_LOOKUP_NEXT_MIDCHAIN) ||
      (adj->lookup_next_index == IP_LOOKUP_NEXT_MCAST_MIDCHAIN))
    {
      dpo_set (&face->dpo, DPO_ADJACENCY_MIDCHAIN,
	       (dpo_proto_t) adj->ia_nh_proto, ai);
      adj_nbr_midchain_stack (ai, &face->dpo);
    }

  return (ADJ_WALK_RC_CONTINUE);
}

/**
 * @brief Retrieve, or create if it doesn't exist, a face from the ip6 local
 * address and returns its dpo. This method adds a lock on the face state.
 *
 * @param dpo: Result of the lookup
 * @param hicnb_flags: Flags that indicate whether the face is an application
 * face or not
 * @param nat_addr: Ip v6 remote address of the face
 * @param sw_if: software interface id of the face
 * @param node_index: vlib edge index to use in the packet processing
 */
always_inline int
hicn_face_ip6_add_and_lock (hicn_face_id_t *index, u8 *hicnb_flags,
			    const ip6_address_t *nat_addr, u32 sw_if,
			    u32 adj_index, u32 node_index)
{
  int ret = HICN_ERROR_NONE;

  /*All (complete) faces are indexed by remote addess as well */
  /* if the face exists, it adds a lock */
  hicn_face_t *face = hicn_face_get ((ip46_address_t *) nat_addr, sw_if,
				     &hicn_face_hashtb, adj_index);

  if (face == NULL)
    {
      hicn_face_id_t idx;
      u8 face_flags = 0;

      hicn_iface_add ((ip46_address_t *) nat_addr, sw_if, &idx, adj_index,
		      face_flags);

      face = hicn_dpoi_get_from_idx (idx);

      if (*hicnb_flags & HICN_BUFFER_FLAGS_FROM_UDP6_TUNNEL &&
	  adj_index != ADJ_INDEX_INVALID)
	{
	  face->dpo.dpoi_type = dpo_type_udp_ip6;
	  face->dpo.dpoi_proto = DPO_PROTO_IP6;
	}
      else if (*hicnb_flags & HICN_BUFFER_FLAGS_FROM_UDP4_TUNNEL &&
	       adj_index != ADJ_INDEX_INVALID)
	{
	  face->dpo.dpoi_type = dpo_type_udp_ip4;
	  face->dpo.dpoi_proto = DPO_PROTO_IP4;
	}
      else
	{
	  face->dpo.dpoi_type = DPO_FIRST;
	  face->dpo.dpoi_proto = DPO_PROTO_IP6;
	}
      face->dpo.dpoi_index = adj_index;
      face->dpo.dpoi_next_node = node_index;

      adj_nbr_walk (face->sw_if, FIB_PROTOCOL_IP6, hicn6_iface_adj_walk_cb,
		    face);

      *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
      *hicnb_flags |= HICN_BUFFER_FLAGS_NEW_FACE;

      *index = idx;

      return ret;
    }
  else
    {
      /* unlock the face. We don't take a lock on each interest we receive */
      hicn_face_id_t face_id = hicn_dpoi_get_index (face);
      hicn_face_unlock_with_id (face_id);
      ret = HICN_ERROR_FACE_ALREADY_CREATED;
    }

  /* Code replicated on purpose */
  *hicnb_flags = HICN_BUFFER_FLAGS_DEFAULT;
  *hicnb_flags |= (face->flags & HICN_FACE_FLAGS_APPFACE_PROD) >>
		  HICN_FACE_FLAGS_APPFACE_PROD_BIT;

  *index = hicn_dpoi_get_index (face);

  return ret;
}

#endif // __HICN_FACE_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
