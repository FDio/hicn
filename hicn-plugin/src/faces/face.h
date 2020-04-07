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

#ifndef __HICN_FACE_H__
#define __HICN_FACE_H__

#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vppinfra/bihash_8_8.h>

typedef u8 hicn_face_flags_t;
typedef index_t hicn_face_id_t;
//typedef dpo_type_t hicn_face_type_t;

/**
 * @file
 *
 * @brief Face
 *
 * This file implements a general face type. A face is carried through nodes as a
 * dpo. The face state (hicn_face_t) is the object pointed by the
 * dpoi_index in the dpo_id_t (see
 * https://docs.fd.io/vpp/18.07/d0/d37/dpo_8h_source.html).
 * A face state that does not contain the indication of the l2 adjacency is an
 * incomplete face (iface), otherwise it is considered to be complete. Each face type
 * provide specific node for processing packets in input or output of complete
 * and incomplete faces.
 */

/**
 * @brief Structure holding the face state. It containes the fields shared among
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
  union {
    dpo_id_t dpo;
    u64 aling_dpo;
  }

  /* Local address of the interface sw_if */
  ip46_address_t nat_addr;

  /* local interface for the local ip address */
  u32 sw_if;

  /* To align a face to 8 bytes */
  u32 padding;

} hicn_face_t;

/* Pool of faces */
extern hicn_face_t *hicn_dpoi_face_pool;

//extern dpo_type_t hicn_face_type;

/* Flags */
/* A face is complete and it stores all the information. A iface lacks of the
   adj index, therefore sending a packet through a iface require a lookup in
   the FIB. */
#define HICN_FACE_FLAGS_DEFAULT        0x00
#define HICN_FACE_FLAGS_FACE           0x01
#define HICN_FACE_FLAGS_IFACE          0x02
#define HICN_FACE_FLAGS_APPFACE_PROD   0x04	/* Currently only IP face can be appface */
#define HICN_FACE_FLAGS_APPFACE_CONS   0x08	/* Currently only IP face can be appface */
#define HICN_FACE_FLAGS_DELETED        0x10

#define HICN_FACE_NULL (hicn_face_id_t) ~0

#define HICN_FACE_FLAGS_APPFACE_PROD_BIT 2
#define HICN_FACE_FLAGS_APPFACE_CONS_BIT 3


#define HICN_BUFFER_FLAGS_DEFAULT 0x00
#define HICN_BUFFER_FLAGS_FACE_IS_APP 0x01

STATIC_ASSERT ((1 << HICN_FACE_FLAGS_APPFACE_PROD_BIT) ==
	       HICN_FACE_FLAGS_APPFACE_PROD,
	       "HICN_FACE_FLAGS_APPFACE_PROD_BIT and  HICN_FACE_FLAGS_APPFACE_PROD must correspond");

STATIC_ASSERT ((1 << HICN_FACE_FLAGS_APPFACE_CONS_BIT) ==
	       HICN_FACE_FLAGS_APPFACE_CONS,
	       "HICN_FACE_FLAGS_APPFACE_CONS_BIT and  HICN_FACE_FLAGS_APPFACE_CONS must correspond");

STATIC_ASSERT ((HICN_FACE_FLAGS_APPFACE_PROD >>
		HICN_FACE_FLAGS_APPFACE_PROD_BIT) ==
	       HICN_BUFFER_FLAGS_FACE_IS_APP,
	       "hicn buffer app flag does not correspond to HICN_FACE_FLAGS_APPFACE_PROD");

STATIC_ASSERT ((HICN_FACE_FLAGS_APPFACE_CONS >>
		HICN_FACE_FLAGS_APPFACE_CONS_BIT) ==
	       HICN_BUFFER_FLAGS_FACE_IS_APP,
	       "hicn buffer app flag does not correspond to HICN_FACE_FLAGS_APPFACE_PROD");

/**
 * @brief Definition of the virtual functin table for an hICN FACE DPO.
 *
 * An hICN dpo is a combination of a dpo context (hicn_dpo_ctx or struct that
 * extends a hicn_dpo_ctx) and a strategy node. The following virtual function table
 * template that glues together the fuction to interact with the context and the
 * creating the dpo
 */
typedef struct hicn_face_vft_s
{
  u8 *(*format_face) (u8 * s, va_list * args);
  /**< Format an hICN face dpo*/
  int (*hicn_face_del) (hicn_face_id_t face_id);
  void (*hicn_face_get_dpo) (hicn_face_t * face, dpo_id_t * dpo);
} hicn_face_vft_t;

#define foreach_hicn_face_counter                      \
  _(INTEREST_RX, 0, "Interest rx")                     \
  _(INTEREST_TX, 1, "Interest tx")                     \
  _(DATA_RX, 2, "Data rx")                     \
  _(DATA_TX, 3, "Data tx")                     \

typedef enum
{
#define _(a,b,c) HICN_FACE_COUNTERS_##a = (b),
  foreach_hicn_face_counter
#undef _
  HICN_N_COUNTER
} hicn_face_counters_t;

extern mhash_t hicn_face_hashtb;

extern const char *HICN_FACE_CTRX_STRING[];

#define get_face_counter_string(ctrxno) (char *)(HICN_FACE_CTRX_STRING[ctrxno])


/* Vector maintaining a dpo per face */
extern dpo_id_t *face_dpo_vec;
extern hicn_face_vft_t *face_vft_vec;

/* Vector holding the set of face names */
extern char **face_type_names_vec;

/* First face type registered in the sytem.*/
extern dpo_type_t first_type;

/* Per-face counters */
extern vlib_combined_counter_main_t *counters;

/**
 * @brief Return the face id from the face state
 *
 * @param Pointer to the face state
 * @return face id
 */
always_inline hicn_face_id_t
hicn_dpoi_get_index (hicn_face_t * face_dpoi)
{
  return face_dpoi - hicn_dpoi_face_pool;
}

/**
 * @brief Return the face from the face id. Face id must be valid.
 *
 * @param dpoi_index Face identifier
 * @return Pointer to the face
 */
always_inline hicn_face_t *
hicn_dpoi_get_from_idx_safe (hicn_face_id_t dpoi_index)
{
  if (!pool_is_free_index(hicn_dpoi_face_pool, dpoi_index))
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
  return pool_len (hicn_dpoi_face_pool) > face_id
    && !pool_is_free_index (hicn_dpoi_face_pool, face_id);
}

/**
 * @brief Add a lock to the face dpo
 *
 * @param dpo Pointer to the face dpo
 */
always_inline void
hicn_face_lock (dpo_id_t * dpo)
{
  hicn_face_t *face;
  face = hicn_dpoi_get_from_idx (dpo->dpoi_index);
  face->locks++;
}

/**
 * @brief Remove a lock to the face dpo. Deallocate the face id locks == 0
 *
 * @param dpo Pointer to the face dpo
 */
always_inline void
hicn_face_unlock_from_dpo (dpo_id_t * dpo)
{
  hicn_face_t *face;
  face = hicn_dpoi_get_from_idx (dpo->dpoi_index);
  face->locks--;
}

/**
 * @brief Remove a lock to the face dpo. Deallocate the face id locks == 0
 *
 * @param dpo Pointer to the face dpo
 */
always_inline void
hicn_face_unlock (hicn_face_id_t face_id)
{
  hicn_face_t *face;
  face = hicn_dpoi_get_from_idx (face_id);
  face->locks--;
}

/**
 * @brief Init the internal structures of the face module
 *
 * Must be called before processing any packet
 */
void hicn_face_module_init (vlib_main_t * vm);

u8 * format_hicn_face (u8 * s, va_list * args);


/**
 * @brief Format all the existing faces
 *
 * @param s Pointer to a previous string. If null it will be initialize
 * @param n Number of input parameters
 * @return String with the faces formatted
 */
u8 *format_hicn_face_all (u8 * s, int n, ...);

/**
 * @brief Delete a face
 *
 * @param face_id Id of the face to delete
 * @return HICN_ERROR_FACE_NOT_FOUND if the face does not exist, otherwise
 * HICN_ERROR_NONE
 */
int hicn_face_del (hicn_face_id_t face_id);

/* FACE IP CODE */

/**
 * @bried vector of faces used to collect faces having the same local address
 *
 */
typedef hicn_face_id_t *hicn_face_vec_t;

typedef struct hicn_input_faces_s_
{
  /* Vector of all possible input faces */
  u32 vec_id;

  /* Preferred face. If an prod_app face is in the vector it will be the preferred one. */
  /* It's not possible to have multiple prod_app face in the same vector, they would have */
  /* the same local address. Every prod_app face is a point-to-point face between the forwarder */
  /* and the application. */
  hicn_face_id_t face_id;

} hicn_face_input_faces_t;

/**
 * Pool containing the vector of possible incoming faces.
 */
extern hicn_face_vec_t *hicn_vec_pool;

/**
 * Hash tables that indexes a face by remote address. For fast lookup when an
 * interest arrives.
 */
extern mhash_t hicn_face_vec_hashtb;


/**
 * Key definition for the mhash table. An ip face is uniquely identified by ip
 * address and the interface id. The ip address can correspond to the remote ip
 * address of the next hicn hop, or to the local address of the receiving
 * interface. The former is used to retrieve the incoming face when an interest
 * is received, the latter when the arring packet is a data.
 */
typedef struct hicn_face_key_s
{
  dpo_id_t dpo;
  ip46_address_t addr;
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
hicn_face_get_key (const ip46_address_t * addr,
                   u32 sw_if, const dpo_id_t * dpo, hicn_face_key_t * key)
{
  key->dpo = *dpo;
  key->addr = *addr;
  key->sw_if = sw_if;
}

/**
 * @brief Get the dpoi from the nat address. Does not add any lock.
 *
 * @param addr Ip v4 address used to create the key for the hash table.
 * @param sw_if Software interface id used to create the key for the hash table.
 * @param hashtb Hash table (remote or local) where to perform the lookup.
 *
 * @result Pointer to the face.
 */
always_inline hicn_face_t *
hicn_face_get (const ip46_address_t * addr, u32 sw_if, mhash_t * hashtb)
{
  hicn_face_key_t key;

  dpo_id_t dpo = DPO_INVALID;

  hicn_face_get_key (addr, sw_if, &dpo, &key);

  hicn_face_id_t *dpoi_index = (hicn_face_id_t *) mhash_get (hashtb,
							     &key);

  return dpoi_index == NULL ? NULL : hicn_dpoi_get_from_idx (*dpoi_index);
}

always_inline hicn_face_t *
hicn_face_get_with_dpo (const ip46_address_t * addr, u32 sw_if, const dpo_id_t * dpo, mhash_t * hashtb)
{
  hicn_face_key_t key;

  hicn_face_get_key (addr, sw_if, dpo, &key);

  hicn_face_id_t *dpoi_index = (hicn_face_id_t *) mhash_get (hashtb,
							     &key);

  return dpoi_index == NULL ? NULL : hicn_dpoi_get_from_idx (*dpoi_index);
}

/**
 * @brief Get the vector of faces from the ip v4 address. Does not add any lock.
 *
 * @param addr Ip v4 address used to create the key for the hash table.
 * @param sw_if Software interface id used to create the key for the hash table.
 * @param hashtb Hash table (remote or local) where to perform the lookup.
 *
 * @result Pointer to the face.
 */
always_inline hicn_face_input_faces_t *
hicn_face_get_vec (const ip46_address_t * addr, u32 sw_if,
                   mhash_t * hashtb)
{
  hicn_face_key_t key;

  dpo_id_t dpo = DPO_INVALID;

  hicn_face_get_key (addr, sw_if, &dpo, &key);
  return (hicn_face_input_faces_t *) mhash_get (hashtb, &key);
}

/**
 * @brief Create a new face ip. API for other modules (e.g., routing)
 *
 * @param local_addr Local ip v4 or v6 address of the face
 * @param remote_addr Remote ip v4 or v6 address of the face
 * @param sw_if interface associated to the face
 * @param is_app_face Boolean to set the face as an application face
 * @param pfaceid Pointer to return the face id
 * @param is_app_prod if HICN_FACE_FLAGS_APPFACE_PROD the face is a local application face, all other values are ignored
 * @return HICN_ERROR_FACE_NO_GLOBAL_IP if the face does not have a globally
 * reachable ip address, otherwise HICN_ERROR_NONE
 */
int hicn_face_add (const dpo_id_t * dpo_nh,
                   ip46_address_t * nat_address,
                   int sw_if,
                   hicn_face_id_t * pfaceid,
                   u8 is_app_prod);

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
hicn_iface_add (ip46_address_t * nat_address, int sw_if,
                hicn_face_id_t * pfaceid, dpo_proto_t proto)
{
  hicn_face_t *face;
  pool_get (hicn_dpoi_face_pool, face);

  clib_memcpy (&(face->nat_addr), nat_address,
	       sizeof (ip46_address_t));
  face->sw_if = sw_if;

  face->dpo.dpoi_type = DPO_FIRST;
  face->dpo.dpoi_proto = proto;
  face->dpo.dpoi_index = INDEX_INVALID;
  face->dpo.dpoi_next_node = 0;
  face->pl_id = (u16) 0;
  face->flags = HICN_FACE_FLAGS_IFACE;
  face->locks = 1;

  hicn_face_key_t key;
  hicn_face_get_key (nat_address, sw_if, &face->dpo, &key);
  *pfaceid = hicn_dpoi_get_index (face);

  mhash_set_mem (&hicn_face_hashtb, &key, (uword *) pfaceid, 0);

  for (int i = 0; i < HICN_N_COUNTER; i++)
    {
      vlib_validate_combined_counter (&counters[(*pfaceid) * HICN_N_COUNTER],
				      i);
      vlib_zero_combined_counter (&counters[(*pfaceid) * HICN_N_COUNTER], i);
    }
}


#endif // __HICN_FACE_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
