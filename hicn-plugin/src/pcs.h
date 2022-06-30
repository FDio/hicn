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

#ifndef __HICN_PCS_H__
#define __HICN_PCS_H__

#include "strategy_dpo_manager.h"
#include "error.h"
#include "cache_policies/cs_policy.h"
#include "faces/face.h"

#include <vppinfra/bihash_24_8.h>

/**
 * @file pcs.h
 *
 * This file implement the PIT and CS which are collapsed in the same
 * structure, therefore an entry is either a PIT entry of a CS entry.
 * The implementation consists of a hash table where each entry of the
 * hash table contains an index to a pool of PIT/CS entries. Each entry
 * contains some counters to maintain the status of the PIT/CS and the
 * reference to the eviction policy for the CS.
 * The default eviction policy is LRU.
 */

/*
 * We need a definition of invalid index. ~0 is reasonable as we don't expect
 * to reach that many element in the PIT.
 */
#define HICN_PCS_INVALID_INDEX ((u32) (~0))

/*
 * The PIT and CS are stored as a union
 */
#define HICN_PIT_NULL_TYPE 0
#define HICN_PIT_TYPE	   1
#define HICN_CS_TYPE	   2

/*
 * Definitions and Forward refs for the time counters we're trying out.
 * Counters are maintained by the background process. TODO.
 */
#define SEC_MS			    1000
#define HICN_INFRA_FAST_TIMER_SECS  1
#define HICN_INFRA_FAST_TIMER_MSECS (HICN_INFRA_FAST_TIMER_SECS * SEC_MS)
#define HICN_INFRA_SLOW_TIMER_SECS  60
#define HICN_INFRA_SLOW_TIMER_MSECS (HICN_INFRA_SLOW_TIMER_SECS * SEC_MS)

#define HICN_CS_ENTRY_OPAQUE_SIZE 32

#define HICN_FACE_DB_INLINE_FACES 8

#define HICN_PIT_BITMAP_SIZE_U64   HICN_PARAM_FACES_MAX / 64
#define HICN_PIT_N_HOP_BITMAP_SIZE HICN_PARAM_FACES_MAX

/*
 * PCS entry. We expect this to fit in 3 cache lines, with a maximum of 8
 * output inline faces and a bitmap of 512 bits. If more faces are needed, a
 * vector will be allocated, but it will endup out of the 3 cache lines.
 */
typedef struct hicn_pcs_entry_s
{
  /*
   * First cache line - shared data
   */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /*
   * Installation/creation time (vpp float units, for now).
   * 8 Bytes
   */
  f64 create_time;

  /*
   * Expiration time (vpp float units, for now)
   * 8 Bytes
   */
  f64 expire_time;

  /*
   * Name
   * 24 bytes
   */
  hicn_name_t name;

  /*
   * Cached hash of the name
   * 8 bytes
   */
  u64 name_hash;

  /*
   * Shared 'flags' octet
   * 1 Byte
   */
  u16 flags;

  /*
   * Number of locks on the PCS entry
   * 2 Bytes
   */
  u16 locks;

  /*
   * Second cache line - PIT or CS data
   */
  CLIB_ALIGN_MARK (second_part, 64);

  union
  {
    struct
    {
      /*
       * Bitmap used to check if interests are retransmission
       */
      u64 bitmap[HICN_PIT_BITMAP_SIZE_U64];

      CLIB_ALIGN_MARK (third_part, 64);

      /*
       * Total number of faces
       */
      u32 n_faces;

      /*
       * Array of indexes of virtual faces
       */
      hicn_face_id_t inline_faces[HICN_FACE_DB_INLINE_FACES];

      /*
       * VPP vector of indexes of additional virtual faces, allocated iff
       * needed
       */
      hicn_face_id_t *faces;
    } pit;
    struct
    { /*
       * Packet buffer, if held
       * 4 Bytes
       */
      u32 cs_pkt_buf;

      /*
       * Linkage for LRU, in the form of hashtable node indexes
       * 8 Bytes
       */
      u32 cs_lru_prev;
      u32 cs_lru_next;
    } cs;
  } u;
} hicn_pcs_entry_t;

STATIC_ASSERT (sizeof (hicn_pcs_entry_t) <= 3 * CLIB_CACHE_LINE_BYTES,
	       "hicn_pcs_entry_t does not fit in 3 cache lines.");

STATIC_ASSERT (0 == offsetof (hicn_pcs_entry_t, cacheline0),
	       "Cacheline0 must be at the beginning of hicn_pcs_entry_t");
STATIC_ASSERT (64 == offsetof (hicn_pcs_entry_t, second_part),
	       "second_part must be at byte 64 of hicn_pcs_entry_t");
STATIC_ASSERT (64 == offsetof (hicn_pcs_entry_t, u.pit.bitmap),
	       "u.pit.bitmap must be at byte 64 of hicn_pcs_entry_t");
STATIC_ASSERT (64 == offsetof (hicn_pcs_entry_t, u.pit.bitmap),
	       "cs_pkt_buf must be at byte 64 of hicn_pcs_entry_t");
STATIC_ASSERT (128 == offsetof (hicn_pcs_entry_t, u.pit.third_part),
	       "third_part must be at byte 128 of hicn_pcs_entry_t");
STATIC_ASSERT (128 == offsetof (hicn_pcs_entry_t, u.pit.n_faces),
	       "u.pit.n_faces must be at byte 128 of hicn_pcs_entry_t");

#define HICN_PCS_ENTRY_CS_FLAG 0x01

/*
 * Forward declarations
 */
always_inline void hicn_pcs_delete_internal (hicn_pit_cs_t *pitcs,
					     hicn_pcs_entry_t *pcs_entry);

always_inline void hicn_pcs_entry_remove_lock (hicn_pit_cs_t *pitcs,
					       hicn_pcs_entry_t *pcs_entry);

/*
 * Overall PIT/CS table.
 */
typedef struct hicn_pit_cs_s
{
  // Hash table mapping name to hash entry index
  clib_bihash_24_8_t pcs_table;

  // Total size of PCS
  u32 max_pit_size;

  // Pool of pcs entries
  hicn_pcs_entry_t *pcs_entries_pool;

  /* Counters for PIT/CS sentries */
  u32 pcs_pit_count;
  u32 pcs_cs_count;
  u32 pcs_pcs_alloc;
  u32 pcs_pcs_dealloc;

  hicn_cs_policy_t policy_state;
} hicn_pit_cs_t;

/************************************************************************
 **************************** Create / Destroy **************************
 ************************************************************************/

void hicn_pit_create (hicn_pit_cs_t *p, u32 max_pit_elt, u32 max_cs_elt);
void hicn_pit_destroy (hicn_pit_cs_t *p);

/************************************************************************
 **************************** Counters getters **************************
 ************************************************************************/

always_inline u32
hicn_pcs_get_pit_count (const hicn_pit_cs_t *pcs)
{
  return pcs->pcs_pit_count;
}

always_inline u32
hicn_pcs_get_cs_count (const hicn_pit_cs_t *pcs)
{
  return pcs->pcs_cs_count;
}

always_inline u32
hicn_pcs_get_pcs_alloc (const hicn_pit_cs_t *pcs)
{
  return pcs->pcs_pcs_alloc;
}

always_inline u32
hicn_pcs_get_pcs_dealloc (const hicn_pit_cs_t *pcs)
{
  return pcs->pcs_pcs_dealloc;
}

always_inline f64
hicn_pcs_get_exp_time (f64 cur_time_sec, u64 lifetime_msec)
{
  return (cur_time_sec + ((f64) lifetime_msec) / SEC_MS);
}

/*
 * Create key from the name struct.
 */
always_inline void
hicn_pcs_get_key_from_name (clib_bihash_kv_24_8_t *kv, const hicn_name_t *name)
{
  kv->key[0] = name->prefix.ip6.as_u64[0];
  kv->key[1] = name->prefix.ip6.as_u64[1];
  kv->key[2] = name->suffix;
}

/************************************************************************
 **************************** LRU Helpers *******************************
 ************************************************************************/

always_inline hicn_cs_policy_t *
hicn_pcs_get_policy_state (hicn_pit_cs_t *pcs)
{
  return &pcs->policy_state;
}

/*
 * Update the CS LRU, moving this item to the head
 */
always_inline void
hicn_pcs_cs_update_lru (hicn_pit_cs_t *pitcs, hicn_pcs_entry_t *entry)
{
  hicn_cs_policy_t *policy_state = hicn_pcs_get_policy_state (pitcs);
  hicn_cs_policy_update (policy_state, pitcs, entry);
}

/*
 * Update the CS LRU, inserting a new item and checking if we need to evict
 */
always_inline void
hicn_pcs_cs_insert_lru (hicn_pit_cs_t *pitcs, hicn_pcs_entry_t *entry)
{
  hicn_cs_policy_t *policy_state = hicn_pcs_get_policy_state (pitcs);
  hicn_cs_policy_insert (policy_state, pitcs, entry);
  pitcs->pcs_cs_count++;

  // If we reached the MAX size of the CS, let's evict one
  if (policy_state->count > policy_state->max)
    {
      // We reached the mac number of CS entry. We need to trim one.
      hicn_pcs_entry_t *pcs_entry;
      hicn_cs_policy_delete_get (policy_state, pitcs, &pcs_entry);

      // Delete evicted entry from hash table
      hicn_pcs_entry_remove_lock (pitcs, pcs_entry);
    }
}

/*
 * Dequeue an entry from the CS LRU
 */
always_inline void
hicn_pcs_cs_dequeue_lru (hicn_pit_cs_t *pitcs, hicn_pcs_entry_t *entry)
{
  // Dequeue the CS entry
  hicn_cs_policy_t *policy_state = hicn_pcs_get_policy_state (pitcs);
  hicn_cs_policy_dequeue (policy_state, pitcs, entry);
}

/************************************************************************
 **************************** PCS Entry APIs ****************************
 ************************************************************************/

/*
 * Create new PCS entry
 */
always_inline hicn_pcs_entry_t *
_hicn_pcs_entry_get (hicn_pit_cs_t *pitcs)
{
  hicn_pcs_entry_t *e;
  pool_get (pitcs->pcs_entries_pool, e);
  pitcs->pcs_pcs_alloc++;

  return e;
}

/*
 * Init pit/cs data block
 */
always_inline void
hicn_pcs_entry_init_data (hicn_pcs_entry_t *p, f64 tnow)
{
  p->flags = 0;
  p->u.pit.n_faces = 0;
  p->locks = 1;
  p->create_time = tnow;
}

/*
 * Free PCS entry
 */
always_inline void
hicn_pcs_entry_put (hicn_pit_cs_t *pitcs, const hicn_pcs_entry_t *entry)
{
  pitcs->pcs_pcs_dealloc++;
  pool_put (pitcs->pcs_entries_pool, entry);
}

/*
 * Get index from the entry.
 */
always_inline u32
hicn_pcs_entry_get_index (const hicn_pit_cs_t *pitcs,
			  const hicn_pcs_entry_t *entry)
{
  ASSERT (!pool_is_free (pitcs->pcs_entries_pool, entry));
  return (u32) (entry - pitcs->pcs_entries_pool);
}

/*
 * Get index from the entry.
 */
always_inline hicn_pcs_entry_t *
hicn_pcs_entry_get_entry_from_index (const hicn_pit_cs_t *pitcs, u32 index)
{
  ASSERT (!pool_is_free_index (pitcs->pcs_entries_pool, index));
  return pool_elt_at_index (pitcs->pcs_entries_pool, index);
}

/*
 * Check if pcs entry is a content store entry
 */
always_inline int
hicn_pcs_entry_is_cs (const hicn_pcs_entry_t *entry)
{
  ASSERT (entry);
  return (entry->flags & HICN_PCS_ENTRY_CS_FLAG);
}

/*
 * Add lock to PIT entry
 */
always_inline void
hicn_pcs_entry_add_lock (hicn_pcs_entry_t *pcs_entry)
{
  pcs_entry->locks++;
}

/*
 * Get/Set expire time from the entry
 */
always_inline f64
hicn_pcs_entry_get_expire_time (hicn_pcs_entry_t *pcs_entry)
{
  return pcs_entry->expire_time;
}

always_inline void
hicn_pcs_entry_set_expire_time (hicn_pcs_entry_t *pcs_entry, f64 expire_time)
{
  pcs_entry->expire_time = expire_time;
}

/*
 * Get/Set create time from the entry
 */
always_inline f64
hicn_pcs_entry_get_create_time (hicn_pcs_entry_t *pcs_entry)
{
  return pcs_entry->create_time;
}

always_inline void
hicn_pcs_entry_set_create_time (hicn_pcs_entry_t *pcs_entry, f64 create_time)
{
  pcs_entry->create_time = create_time;
}

/*
 * Remove a lock in the entry and delete it if there are no pending lock and
 * the entry is marked as to be deleted
 */
always_inline void
hicn_pcs_entry_remove_lock (hicn_pit_cs_t *pitcs, hicn_pcs_entry_t *pcs_entry)
{
  // Make sure we are removing a lock on a valid entry
  ASSERT (pcs_entry->locks > 0);

  if (--pcs_entry->locks == 0)
    {
      hicn_pcs_delete_internal (pitcs, pcs_entry);
    }
}

/************************************************************************
 **************************** CS Entry APIs *****************************
 ************************************************************************/

/*
 * Create new CS entry
 */
always_inline hicn_pcs_entry_t *
hicn_pcs_entry_cs_get (hicn_pit_cs_t *pitcs, f64 tnow, u32 buffer_index)
{
  hicn_pcs_entry_t *ret = _hicn_pcs_entry_get (pitcs);
  hicn_pcs_entry_init_data (ret, tnow);
  ret->flags = HICN_PCS_ENTRY_CS_FLAG;
  ret->u.cs.cs_lru_next = HICN_CS_POLICY_END_OF_CHAIN;
  ret->u.cs.cs_lru_prev = HICN_CS_POLICY_END_OF_CHAIN;

  return ret;
}

always_inline u32
hicn_pcs_entry_cs_get_buffer (hicn_pcs_entry_t *pcs_entry)
{
  return pcs_entry->u.cs.cs_pkt_buf;
}

always_inline void
hicn_pcs_entry_cs_set_buffer (hicn_pcs_entry_t *pcs_entry, u32 buffer_index)
{
  pcs_entry->u.cs.cs_pkt_buf = buffer_index;
}

always_inline u32
hicn_pcs_entry_cs_get_next (hicn_pcs_entry_t *pcs_entry)
{
  return pcs_entry->u.cs.cs_lru_next;
}

always_inline void
hicn_pcs_entry_cs_set_next (hicn_pcs_entry_t *pcs_entry, u32 next)
{
  pcs_entry->u.cs.cs_lru_next = next;
}

always_inline u32
hicn_pcs_entry_cs_get_prev (hicn_pcs_entry_t *pcs_entry)
{
  return pcs_entry->u.cs.cs_lru_prev;
}

always_inline void
hicn_pcs_entry_cs_set_prev (hicn_pcs_entry_t *pcs_entry, u32 prev)
{
  pcs_entry->u.cs.cs_lru_prev = prev;
}

/* Init pit/cs data block (usually inside hash table node) */
always_inline void
hicn_pcs_entry_cs_free_data (hicn_pcs_entry_t *p)
{
  CLIB_UNUSED (u32 bi) = hicn_pcs_entry_cs_get_buffer (p);

#ifndef HICN_PCS_TESTING
  // Release buffer
  vlib_buffer_free_one (vlib_get_main (), bi);
#endif

  // Reset the vlib_buffer index
  hicn_pcs_entry_cs_set_buffer (p, ~0);
}

/************************************************************************
 **************************** PIT Entry APIs ****************************
 ************************************************************************/

/*
 * Init pit/cs data block
 */
always_inline hicn_pcs_entry_t *
hicn_pcs_entry_pit_get (hicn_pit_cs_t *pitcs, f64 tnow,
			hicn_lifetime_t lifetime)
{
  hicn_pcs_entry_t *ret = _hicn_pcs_entry_get (pitcs);
  hicn_pcs_entry_init_data (ret, tnow);
  clib_memset_u64 (ret->u.pit.bitmap, 0, HICN_PIT_BITMAP_SIZE_U64);
  ret->u.pit.n_faces = 0;
  ret->expire_time = hicn_pcs_get_exp_time (tnow, lifetime);

  return ret;
}

/*
 * Free pit/cs data block
 */
always_inline void
hicn_pcs_entry_pit_free_data (hicn_pcs_entry_t *p)
{
  // Nothing to do for the moment
}

always_inline u32
hicn_pcs_entry_pit_get_n_faces (hicn_pcs_entry_t *p)
{
  return p->u.pit.n_faces;
}

/*
 * Get face id at index index
 */
always_inline hicn_face_id_t
hicn_pcs_entry_pit_get_dpo_face (const hicn_pcs_entry_t *pit_entry, u32 index)
{
  // Make sure the entry is PIT
  ASSERT (!hicn_pcs_entry_is_cs (pit_entry));

  // Make sure the index is valid
  ASSERT (index < pit_entry->u.pit.n_faces);

  if (index < HICN_FACE_DB_INLINE_FACES)
    return pit_entry->u.pit.inline_faces[index];
  else
    return pit_entry->u.pit.faces[index - HICN_FACE_DB_INLINE_FACES];
}

always_inline void
hicn_pcs_entry_pit_add_face (hicn_pcs_entry_t *pit_entry,
			     hicn_face_id_t face_id)
{
  ASSERT (face_id < HICN_PARAM_FACES_MAX);

  if (pit_entry->u.pit.n_faces < HICN_FACE_DB_INLINE_FACES)
    {
      pit_entry->u.pit.inline_faces[pit_entry->u.pit.n_faces] = face_id;
    }
  else
    {
      vec_validate_aligned (pit_entry->u.pit.faces,
			    pit_entry->u.pit.n_faces -
			      HICN_FACE_DB_INLINE_FACES,
			    CLIB_CACHE_LINE_BYTES);
      pit_entry->u.pit
	.faces[pit_entry->u.pit.n_faces - HICN_FACE_DB_INLINE_FACES] = face_id;
    }

  pit_entry->u.pit.n_faces++;

  clib_bitmap_set_no_check (pit_entry->u.pit.bitmap, face_id, 1);
}

/*
 * Search face in db
 */
always_inline u8
hicn_pcs_entry_pit_search (const hicn_pcs_entry_t *pit_entry,
			   hicn_face_id_t face_id)
{
  ASSERT (face_id < HICN_PARAM_FACES_MAX);
  return clib_bitmap_get_no_check ((uword *) pit_entry->u.pit.bitmap, face_id);
}

/************************************************************************
 **************************** Lookup API ********************************
 ************************************************************************/

/**
 * @brief Perform one lookup in the PIT/CS table using the provided name.
 *
 * @param pitcs the PIT/CS table
 * @param name the name to lookup
 * @param pcs_entry [RETURN] if the entry exists, the entry is returned
 * @return HICN_ERROR_NONE if the entry is found, HICN_ERROR_PCS_NOT_FOUND
 * otherwise
 */
always_inline int
hicn_pcs_lookup_one (hicn_pit_cs_t *pitcs, const hicn_name_t *name,
		     hicn_pcs_entry_t **pcs_entry)
{
  int ret;

  // Construct the lookup key
  clib_bihash_kv_24_8_t kv;
  hicn_pcs_get_key_from_name (&kv, name);

  // Do a search in the has table
  ret = clib_bihash_search_inline_24_8 (&pitcs->pcs_table, &kv);

  if (PREDICT_FALSE (ret != 0))
    {
      *pcs_entry = NULL;
      return HICN_ERROR_PCS_NOT_FOUND;
    }

  // Retrieve entry from pool
  *pcs_entry = hicn_pcs_entry_get_entry_from_index (pitcs, kv.value);

  // If entry found and it is a CS entry, let's update the LRU
  if (hicn_pcs_entry_is_cs (*pcs_entry))
    {
      hicn_pcs_cs_update_lru (pitcs, *pcs_entry);
    }

  // If the entry is found, return it
  return HICN_ERROR_NONE;
}

/************************************************************************
 **************************** PCS Delete API ****************************
 ************************************************************************/

/*
 * Delete a PIT/CS entry from the hashtable.
 * The caller's pointers are zeroed! If cs_trim is true, entry has already
 * been removed from lru list The main purpose of this wrapper is helping
 * maintain the per-PIT stats.
 */
always_inline void
hicn_pcs_delete_internal (hicn_pit_cs_t *pitcs, hicn_pcs_entry_t *pcs_entry)
{
  if (pcs_entry->flags & HICN_PCS_ENTRY_CS_FLAG)
    {
      // Remove entry from LRU list
      hicn_pcs_cs_dequeue_lru (pitcs, pcs_entry);

      // Update counters
      pitcs->pcs_cs_count--;

      // Free data
      hicn_pcs_entry_cs_free_data (pcs_entry);

      // Sanity check
      ASSERT ((pcs_entry->u.cs.cs_lru_prev == HICN_CS_POLICY_END_OF_CHAIN) &&
	      (pcs_entry->u.cs.cs_lru_prev == pcs_entry->u.cs.cs_lru_next));
    }
  else
    {
      // Update counters
      pitcs->pcs_pit_count--;
      // Flush faces
      //       hicn_faces_flush (&(pcs_entry->u.pit.faces));
    }

  // Delete entry from hash table
  clib_bihash_kv_24_8_t kv;
  hicn_pcs_get_key_from_name (&kv, &pcs_entry->name);
  clib_bihash_add_del_24_8 (&pitcs->pcs_table, &kv, 0 /* is_add */);

  // Free pool entry
  hicn_pcs_entry_put (pitcs, pcs_entry);
}

/************************************************************************
 **************************** PCS Insert API ****************************
 ************************************************************************/

always_inline int
hicn_pcs_insert (hicn_pit_cs_t *pitcs, hicn_pcs_entry_t *entry,
		 const hicn_name_t *name)
{
  clib_bihash_kv_24_8_t kv;
  u32 index = hicn_pcs_entry_get_index (pitcs, entry);

  // Construct KV pair and try to add it to hash table
  hicn_pcs_get_key_from_name (&kv, name);
  kv.value = index;

  // Get name hash
  entry->name_hash = clib_bihash_hash_24_8 (&kv);
  entry->name = *name;

  return clib_bihash_add_del_24_8 (&pitcs->pcs_table, &kv,
				   2 /* add_but_not_replace */);
}

/**
 * @brief Insert a CS entry in the PIT/CS table. This function DOES NOT check
 * if the KV is already present in the table. It expects the caller to check
 * this before trying to insert the new entry.
 *
 * @param pitcs the PIT/CS table
 * @param entry the entry to insert
 * @param name the name to use to compute the key
 * @return always_inline
 */
always_inline int
hicn_pcs_cs_insert (hicn_pit_cs_t *pitcs, hicn_pcs_entry_t *entry,
		    const hicn_name_t *name)
{
  // Make sure this is a CS entry
  ASSERT (hicn_pcs_entry_is_cs (entry));

  int ret = hicn_pcs_insert (pitcs, entry, name);

  // Make sure insertion happened
  ASSERT (ret == 0);

  // New entry, update LRU
  hicn_pcs_cs_insert_lru (pitcs, entry);

  return HICN_ERROR_NONE;
}

/**
 * @brief Insert a PIT entry in the PIT/CS table. This function DOES NOT check
 * if the KV is already present in the table. It is expected the caller checks
 * this before trying to insert the new entry.
 *
 * @param pitcs
 * @param name
 * @param pcs_entry_index
 * @param dpo_ctx_id
 * @param vft_id
 * @param is_cs
 * @return always_inline
 */
always_inline int
hicn_pcs_pit_insert (hicn_pit_cs_t *pitcs, hicn_pcs_entry_t *entry,
		     const hicn_name_t *name)
{
  // Insert entry into hash table
  int ret = hicn_pcs_insert (pitcs, entry, name);

  // Make sure insertion happened
  ASSERT (ret == 0);

  // Increment the number of PIT entries if insertion happened
  pitcs->pcs_pit_count++;

  return HICN_ERROR_NONE;
}

/************************************************************************
 ************************** PCS Conversion API **************************
 ************************************************************************/

/**
 * @brief Convert a PIT entry to a CS entry.
 *
 * @param vm
 * @param pitcs
 * @param pcs_entry
 * @param hash_entry
 * @param node
 * @param dpo_vft
 * @param hicn_dpo_id
 * @return always_inline
 */
always_inline void
hicn_pit_to_cs (hicn_pit_cs_t *pitcs, hicn_pcs_entry_t *pit_entry,
		u32 buffer_index)
{
  // Different from the insert node. In here we don't need to add a new
  // hash entry.
  pitcs->pcs_pit_count--;

  // Flush faces
  //   hicn_faces_flush (&(pit_entry->u.pit.faces));

  // Set the flags
  pit_entry->flags = HICN_PCS_ENTRY_CS_FLAG;

  // Set the buffer index
  pit_entry->u.cs.cs_pkt_buf = buffer_index;

  hicn_pcs_cs_insert_lru (pitcs, pit_entry);
}

#endif /* __HICN_PCS_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
