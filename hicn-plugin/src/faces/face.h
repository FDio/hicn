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
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include "../hicn.h"

typedef u8 hicn_face_flags_t;
typedef index_t hicn_face_id_t;
typedef dpo_type_t hicn_face_type_t;

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
 * @brief Fields shared among all the different types of faces
 */
typedef struct __attribute__ ((packed)) hicn_face_shared_s
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

  /* Adjacency for the neighbor (4B) */
  adj_index_t adj;

  /* local interface for the local ip address */
  u32 sw_if;

  /* Face id corresponding to the global face pool (4B) */
  union
  {
    hicn_face_type_t face_type;
    u32 int_face_type;		//To force the face_type_t to be 4B
  };

} hicn_face_shared_t;

/**
 * @brief Structure holding the face state. It containes the fields shared among
 * all the types of faces as well it leaves some space for storing additional
 * information specific to each type.
 */
typedef struct __attribute__ ((packed)) hicn_face_s
{
  /* Additional space to fill with face_type specific information */
  u8 data[2 * CLIB_CACHE_LINE_BYTES - sizeof (hicn_face_shared_t)];
  hicn_face_shared_t shared;
} hicn_face_t;

/* Pool of faces */
extern hicn_face_t *hicn_dpoi_face_pool;

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
  face->shared.locks++;
}

/**
 * @brief Remove a lock to the face dpo. Deallocate the face id locks == 0
 *
 * @param dpo Pointer to the face dpo
 */
always_inline void
hicn_face_unlock (dpo_id_t * dpo)
{
  hicn_face_t *face;
  face = hicn_dpoi_get_from_idx (dpo->dpoi_index);
  face->shared.locks--;
}

/**
 * @brief Init the internal structures of the face module
 *
 * Must be called before processing any packet
 */
void hicn_face_module_init (vlib_main_t * vm);

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

/**
 * @brief Return the virtual function table corresponding to the face type
 *
 * @param face_type Type of the face
 * @return NULL if the face type does not exist
 */
hicn_face_vft_t *hicn_face_get_vft (hicn_face_type_t face_type);

/**
 * @brief Register a new face type
 *
 * @param face_type Type of the face
 * @param vft Virtual Function table for the new face type
 */
void register_face_type (hicn_face_type_t face_type, hicn_face_vft_t * vft,
			 char *name);
#endif // __HICN_FACE_H__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
