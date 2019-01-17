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

#ifndef __HICN_FACE_DB_H__
#define __HICN_FACE_DB_H__

#include <vnet/dpo/dpo.h>
#include "faces/face.h"

/**
 * @File
 *
 * Define a face db that is store in every pit entry. A face db containes a list
 * of incoming faces for interest packets that are used to forward data packets
 * on the interests' reverse path
 */

/* Must be power of two */
#define HICN_FACE_DB_INLINE_FACES 4

#define HICN_PIT_N_HOP_BITMAP_SIZE HICN_PARAM_PIT_ENTRY_PHOPS_MAX

#define HICN_PIT_N_HOP_BUCKET (HICN_PARAM_PIT_ENTRY_PHOPS_MAX - HICN_FACE_DB_INLINE_FACES)

STATIC_ASSERT ((HICN_PIT_N_HOP_BUCKET & (HICN_PIT_N_HOP_BUCKET - 1)) == 0,
	       "HICN_PARAM_PIT_ENTRY_PHOP_MAX must be a power of 2 + 4");

/* Takes 2 cache lines */
typedef struct __attribute__ ((packed)) hicn_face_bucket_s
{
  /* Array of indexes of virtual faces */
  dpo_id_t faces[HICN_PIT_N_HOP_BUCKET];

  CLIB_CACHE_LINE_ALIGN_MARK (cache_line1);

  /* Used to check if interests are retransmission */
  u8 bitmap[HICN_PIT_N_HOP_BITMAP_SIZE];

} hicn_face_bucket_t;

extern hicn_face_bucket_t *hicn_face_bucket_pool;

typedef struct __attribute__ ((packed)) hicn_face_db_s
{
  /* 19B + 1B = 20B */
  /* Equal to one or zero */
  u8 is_overflow;

  /* Number of faces in the last bucket */
  /* Or next availabe entry for storing a dpo_id_t */
  /* 20B + 4B = 24B */
  u32 n_faces;

  /* 24B + 32B (8*4) = 56B */
  /* Array of indexes of virtual faces */
  dpo_id_t inline_faces[HICN_FACE_DB_INLINE_FACES];

  /* 56B + 4B = 60B */
  u32 next_bucket;

  /* 60B + 4B = 64B */
  u32 align;
  //align back to 64

} hicn_face_db_t;

always_inline dpo_id_t *
hicn_face_db_get_dpo_face (u32 index, hicn_face_db_t * face_db)
{
  ASSERT (index < face_db->n_faces);

  return index < HICN_FACE_DB_INLINE_FACES ? &(face_db->inline_faces[index]) :
    &(pool_elt_at_index (hicn_face_bucket_pool, face_db->next_bucket)->faces
      [(index - HICN_FACE_DB_INLINE_FACES) & (HICN_PIT_N_HOP_BUCKET - 1)]);
}

always_inline void
hicn_face_db_init (int max_element)
{
  pool_init_fixed (hicn_face_bucket_pool, max_element);
}

always_inline hicn_face_bucket_t *
hicn_face_db_get_bucket (u32 bucket_index)
{
  return pool_elt_at_index (hicn_face_bucket_pool, bucket_index);
}

always_inline void
hicn_face_db_add_face_dpo (dpo_id_t * dpo, hicn_face_db_t * face_db)
{
  ASSERT (dpo->dpoi_index != ~0);

  hicn_face_bucket_t *faces_bkt =
    pool_elt_at_index (hicn_face_bucket_pool, face_db->next_bucket);

  dpo_id_t *face =
    face_db->n_faces <
    HICN_FACE_DB_INLINE_FACES ? &(face_db->inline_faces[face_db->n_faces]) :
    &(faces_bkt->faces
      [(face_db->n_faces -
	HICN_FACE_DB_INLINE_FACES) & (HICN_PIT_N_HOP_BUCKET - 1)]);

  clib_memcpy (face, dpo, sizeof (dpo_id_t));

  /* This access the dpoi to increase the lock */
  dpo_lock (dpo);

  u32 bitmap_index = dpo->dpoi_index % HICN_PIT_N_HOP_BITMAP_SIZE;
  faces_bkt->bitmap[bitmap_index] |= 0x01;
  face_db->n_faces++;
}

always_inline u8
hicn_face_search (dpo_id_t * dpo, hicn_face_db_t * face_db)
{
  hicn_face_bucket_t *faces_bkt =
    pool_elt_at_index (hicn_face_bucket_pool, face_db->next_bucket);
  u32 bitmap_index = dpo->dpoi_index % HICN_PIT_N_HOP_BITMAP_SIZE;

  return faces_bkt->bitmap[bitmap_index] & 0x01;
}

always_inline void
hicn_faces_flush (hicn_face_db_t * face_db)
{
  hicn_face_bucket_t *faces_bkt =
    pool_elt_at_index (hicn_face_bucket_pool, face_db->next_bucket);
  clib_memset_u64 (&(faces_bkt->bitmap), 0, HICN_PIT_N_HOP_BITMAP_SIZE / 8);
  face_db->n_faces = 0;
  pool_put_index (hicn_face_bucket_pool, face_db->next_bucket);
}


#endif /* // __HICN_FACE_DB_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
