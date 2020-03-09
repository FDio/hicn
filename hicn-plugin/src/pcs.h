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

#ifndef __HICN_PCS_H__
#define __HICN_PCS_H__

#include "hashtb.h"
#include "face_db.h"
#include "strategy_dpo_manager.h"
#include "error.h"
#include "cache_policies/cs_policy.h"
#include "faces/face.h"
#include "faces/ip/dpo_ip.h"
#include "faces/app/face_prod.h"

/* The PIT and CS are stored as a union */
#define HICN_PIT_NULL_TYPE 0
#define HICN_PIT_TYPE      1
#define HICN_CS_TYPE       2

/*
 * Definitions and Forward refs for the time counters we're trying out.
 * Counters are maintained by the background process.
 */
#define SEC_MS 1000
#define HICN_INFRA_FAST_TIMER_SECS  1
#define HICN_INFRA_FAST_TIMER_MSECS (HICN_INFRA_FAST_TIMER_SECS * SEC_MS)
#define HICN_INFRA_SLOW_TIMER_SECS  60
#define HICN_INFRA_SLOW_TIMER_MSECS (HICN_INFRA_SLOW_TIMER_SECS * SEC_MS)

/*
 * Max number of incoming (interest) faces supported, for now. Note that
 * changing this may change alignment within the PIT struct, so be careful.
 */
typedef struct __attribute__ ((packed)) hicn_pcs_shared_s
{

  /* Installation/creation time (vpp float units, for now) */
  f64 create_time;

  /* Expiration time (vpp float units, for now) */
  f64 expire_time;

  /* Shared 'flags' octet */
  u8 entry_flags;

  /* Needed to align for the pit or cs portion */
  u8 padding;
} hicn_pcs_shared_t;

#define HICN_PCS_ENTRY_CS_FLAG 0x01

/*
 * PIT entry, unioned with a CS entry below
 */
typedef struct __attribute__ ((packed)) hicn_pit_entry_s
{

  /* Shared size 8 + 8 + 2 = 18B */

  /*
   * Egress next hop (containes the egress face) This id refers to the
   * nh
   */
  /* choosen in the next_hops array of the dpo */
  /* 18B + 1B = 19B */
  u8 pe_txnh;

  /* Array of faces */
  /* 24B + 32B (8B*4) =56B */
  hicn_face_db_t faces;

} hicn_pit_entry_t;

#define HICN_CS_ENTRY_OPAQUE_SIZE HICN_HASH_NODE_APP_DATA_SIZE - 40

/*
 * CS entry, unioned with a PIT entry below
 */
typedef struct __attribute__ ((packed)) hicn_cs_entry_s
{
  /* 22B + 2B = 24B */
  u16 align;

  /* Packet buffer, if held */
  /* 18B + 4B = 22B */
  u32 cs_pkt_buf;

  /* Ingress face */
  /* 24B + 8B = 32B */
  //Fix alignment issues
  union
  {
    dpo_id_t cs_rxface;
    u64 cs_rxface_u64;
  };

  /* Linkage for LRU, in the form of hashtable node indexes */
  /* 32B + 8B = 40B */
  u32 cs_lru_prev;
  u32 cs_lru_next;

  /* Reserved for implementing cache policy different than LRU */
  /* 40B + (64 - 40)B = 64B */
  u8 opaque[HICN_CS_ENTRY_OPAQUE_SIZE];


} __attribute__ ((packed)) hicn_cs_entry_t;

/*
 * Combined PIT/CS entry data structure, embedded in a hashtable entry after
 * the common hashtable preamble struct. This MUST fit in the available
 * (fixed) space in a hashtable node.
 */
typedef struct hicn_pcs_entry_s
{

  hicn_pcs_shared_t shared;

  union
  {
    hicn_pit_entry_t pit;
    hicn_cs_entry_t cs;
  } u;
} hicn_pcs_entry_t;


/*
 * Overall PIT/CS table, based on the common hashtable
 */
typedef struct hicn_pit_cs_s
{

  hicn_hashtb_t *pcs_table;

  /* Counters for PIT/CS sentries */
  u32 pcs_pit_count;
  u32 pcs_cs_count;
  u32 pcs_cs_dealloc;
  u32 pcs_pit_dealloc;

  /* Total size of PCS */
  u32 pcs_size;

  /* Memory reserved for appfaces */
  u32 pcs_app_max;
  u32 pcs_app_count;

  hicn_cs_policy_t policy_state;
  hicn_cs_policy_vft_t policy_vft;

} hicn_pit_cs_t;

/* Functions declarations */
int hicn_pit_create (hicn_pit_cs_t * p, u32 num_elems);

always_inline void
hicn_pit_to_cs (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		hicn_pcs_entry_t * pcs_entry, hicn_hash_entry_t * hash_entry,
		hicn_hash_node_t * node, const hicn_dpo_vft_t * dpo_vft,
		dpo_id_t * hicn_dpo_id, dpo_id_t * inface_id, u8 is_appface);

always_inline void
hicn_pcs_cs_update (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		    hicn_pcs_entry_t * old_entry, hicn_pcs_entry_t * entry, hicn_hash_node_t * node);

always_inline void
hicn_pcs_cs_delete (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		    hicn_pcs_entry_t ** pcs_entry, hicn_hash_node_t ** node,
		    hicn_hash_entry_t * hash_entry,
		    const hicn_dpo_vft_t * dpo_vft, dpo_id_t * hicn_dpo_id);

always_inline int
hicn_pcs_cs_insert (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		    hicn_pcs_entry_t * entry, hicn_hash_node_t * node,
		    hicn_hash_entry_t ** hash_entry, u64 hashval,
		    u32 * node_id, index_t * dpo_ctx_id, u8 * vft_id, u8 * is_cs,
		    u8 * hash_entry_id, u32 * bucket_id,
		    u8 * bucket_is_overflow);

always_inline int
hicn_pcs_cs_insert_update (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
			   hicn_pcs_entry_t * entry, hicn_hash_node_t * node,
			   hicn_hash_entry_t ** hash_entry, u64 hashval,
			   u32 * node_id, index_t * dpo_ctx_id, u8 * vft_id,
			   u8 * is_cs, u8 * hash_entry_id, u32 * bucket_id,
			   u8 * bucket_is_overflow, dpo_id_t * inface);

always_inline int
hicn_pcs_pit_insert (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t * entry,
		     hicn_hash_node_t * node, hicn_hash_entry_t ** hash_entry,
		     u64 hashval, u32 * node_id, index_t * dpo_ctx_id, u8 * vft_id,
		     u8 * is_cs, u8 * hash_entry_id, u32 * bucket_id,
		     u8 * bucket_is_overflow);

always_inline void
hicn_pcs_pit_delete (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t ** pcs_entryp,
		     hicn_hash_node_t ** node, vlib_main_t * vm,
		     hicn_hash_entry_t * hash_entry,
		     const hicn_dpo_vft_t * dpo_vft, dpo_id_t * hicn_dpo_id);

always_inline int
hicn_pcs_insert (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		 hicn_pcs_entry_t * entry, hicn_hash_node_t * node,
		 hicn_hash_entry_t ** hash_entry, u64 hashval, u32 * node_id,
		 index_t * dpo_ctx_id, u8 * vft_id, u8 * is_cs, u8 * hash_entry_id,
		 u32 * bucket_id, u8 * bucket_is_overflow);

always_inline void
hicn_pcs_delete (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t ** pcs_entryp,
		 hicn_hash_node_t ** node, vlib_main_t * vm,
		 hicn_hash_entry_t * hash_entry,
		 const hicn_dpo_vft_t * dpo_vft, dpo_id_t * hicn_dpo_id);

always_inline void
hicn_pcs_remove_lock (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t ** pcs_entryp,
		      hicn_hash_node_t ** node, vlib_main_t * vm,
		      hicn_hash_entry_t * hash_entry,
		      const hicn_dpo_vft_t * dpo_vft, dpo_id_t * hicn_dpo_id);

always_inline void
hicn_cs_delete_trimmed (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t ** pcs_entryp,
			hicn_hash_entry_t * hash_entry,
			hicn_hash_node_t ** node, vlib_main_t * vm);

/* Function implementation */
/* Accessor for pit/cs data inside hash table node */
static inline hicn_pcs_entry_t *
hicn_pit_get_data (hicn_hash_node_t * node)
{
  return (hicn_pcs_entry_t *) (hicn_hashtb_node_data (node));
}

/* Init pit/cs data block (usually inside hash table node) */
static inline void
hicn_pit_init_data (hicn_pcs_entry_t * p)
{
  p->shared.entry_flags = 0;
  p->u.pit.faces.n_faces = 0;
  p->u.pit.faces.is_overflow = 0;
  hicn_face_bucket_t *face_bkt;
  pool_get (hicn_face_bucket_pool, face_bkt);

  p->u.pit.faces.next_bucket = face_bkt - hicn_face_bucket_pool;
}

/* Init pit/cs data block (usually inside hash table node) */
static inline void
hicn_cs_init_data (hicn_pcs_entry_t * p)
{
  p->shared.entry_flags = 0;
  p->u.pit.faces.n_faces = 0;
  p->u.pit.faces.is_overflow = 0;
}


static inline f64
hicn_pcs_get_exp_time (f64 cur_time_sec, u64 lifetime_msec)
{
  return (cur_time_sec + ((f64) lifetime_msec) / SEC_MS);
}

/*
 * Configure CS LRU limit. Zero is accepted, means 'no limit', probably not a
 * good choice.
 */
static inline void
hicn_pit_set_lru_max (hicn_pit_cs_t * p, u32 limit)
{
  p->policy_state.max = limit;
}

/*
 * Configure CS LRU limit. Zero is accepted, means 'no limit', probably not a
 * good choice.
 */
static inline void
hicn_pit_set_lru_app_max (hicn_pit_cs_t * p, u32 limit)
{
  p->pcs_app_max = limit;
}

/*
 * Accessor for PIT interest counter.
 */
static inline u32
hicn_pit_get_int_count (const hicn_pit_cs_t * pitcs)
{
  return (pitcs->pcs_pit_count);
}

/*
 * Accessor for PIT cs entries counter.
 */
static inline u32
hicn_pit_get_cs_count (const hicn_pit_cs_t * pitcs)
{
  return (pitcs->pcs_cs_count);
}

static inline u32
hicn_pcs_get_ntw_count (const hicn_pit_cs_t * pitcs)
{
  return (pitcs->policy_state.count);
}

static inline u32
hicn_pit_get_htb_bucket_count (const hicn_pit_cs_t * pitcs)
{
  return (pitcs->pcs_table->ht_overflow_buckets_used);
}

static inline int
hicn_cs_enabled (hicn_pit_cs_t * pit)
{
  switch (HICN_FEATURE_CS)
    {
    case 0:
    default:
      return (0);
    case 1:
      return (pit->policy_state.max > 0);
    }
}

/*
 * Delete a PIT/CS entry from the hashtable, freeing the hash node struct.
 * The caller's pointers are zeroed! If cs_trim is true, entry has already
 * been removed from lru list The main purpose of this wrapper is helping
 * maintain the per-PIT stats.
 */
always_inline void
hicn_pcs_delete_internal (hicn_pit_cs_t * pitcs,
			  hicn_pcs_entry_t ** pcs_entryp,
			  hicn_hash_entry_t * hash_entry,
			  hicn_hash_node_t ** node, vlib_main_t * vm,
			  const hicn_dpo_vft_t * dpo_vft,
			  dpo_id_t * hicn_dpo_id)
{
  hicn_pcs_entry_t *pcs = *pcs_entryp;

  ASSERT (pcs == hicn_hashtb_node_data (*node));

  if (hash_entry->he_flags & HICN_HASH_ENTRY_FLAG_CS_ENTRY)
    {
      pitcs->pcs_cs_dealloc++;
      /* Free any associated packet buffer */
      vlib_buffer_free_one (vm, pcs->u.cs.cs_pkt_buf);
      pcs->u.cs.cs_pkt_buf = ~0;
      ASSERT ((pcs->u.cs.cs_lru_prev == 0)
	      && (pcs->u.cs.cs_lru_prev == pcs->u.cs.cs_lru_next));
    }
  else
    {
      pitcs->pcs_pit_dealloc++;
      hicn_strategy_dpo_ctx_unlock (hicn_dpo_id);

      /* Flush faces */
      hicn_faces_flush (&(pcs->u.pit.faces));
    }

  hicn_hashtb_delete (pitcs->pcs_table, node, hash_entry->he_msb64);
  *pcs_entryp = NULL;
}

/*
 * Convert a PIT entry into a CS entry (assumes that the entry is already in
 * the hashtable.) This is primarily here to maintain the internal counters.
 */
always_inline void
hicn_pit_to_cs (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		hicn_pcs_entry_t * pcs_entry, hicn_hash_entry_t * hash_entry,
		hicn_hash_node_t * node, const hicn_dpo_vft_t * dpo_vft,
		dpo_id_t * hicn_dpo_id, dpo_id_t * inface_id, u8 is_appface)
{

  /*
   * Different from the insert node. In here we don't need to add a new
   * hash entry.
   */
  pitcs->pcs_pit_count--;
  hicn_strategy_dpo_ctx_unlock (hicn_dpo_id);
  /* Flush faces */
  hicn_faces_flush (&(pcs_entry->u.pit.faces));

  hash_entry->he_flags |= HICN_HASH_ENTRY_FLAG_CS_ENTRY;
  node->hn_flags |= HICN_HASH_NODE_CS_FLAGS;
  pcs_entry->shared.entry_flags |= HICN_PCS_ENTRY_CS_FLAG;

  pcs_entry->u.cs.cs_rxface = *inface_id;

  /* Update the CS according to the policy */
  hicn_cs_policy_t *policy_state;
  hicn_cs_policy_vft_t *policy_vft;

  if (is_appface)
    {
      dpo_id_t *face_dpo = (dpo_id_t *) & (pcs_entry->u.cs.cs_rxface);
      hicn_face_t *face = hicn_dpoi_get_from_idx (face_dpo->dpoi_index);
      hicn_face_prod_t *prod_face = (hicn_face_prod_t *) face->data;
      policy_state = &prod_face->policy;
      policy_vft = &prod_face->policy_vft;
    }
  else
    {
      policy_state = &pitcs->policy_state;
      policy_vft = &pitcs->policy_vft;
    }

  policy_vft->hicn_cs_insert (pitcs, node, pcs_entry, policy_state);
  pitcs->pcs_cs_count++;

  if (policy_state->count > policy_state->max)
    {
      hicn_hash_node_t *node;
      hicn_pcs_entry_t *pcs_entry;
      hicn_hash_entry_t *hash_entry;
      policy_vft->hicn_cs_delete_get (pitcs, policy_state,
				      &node, &pcs_entry, &hash_entry);


      /*
       * We don't have to decrease the lock (therefore we cannot
       * use hicn_pcs_cs_delete function)
       */
      policy_vft->hicn_cs_dequeue (pitcs, node, pcs_entry, policy_state);

      hicn_cs_delete_trimmed (pitcs, &pcs_entry, hash_entry, &node, vm);

      /* Update the global CS counter */
      pitcs->pcs_cs_count--;
    }
}

/* Functions specific for PIT or CS */

always_inline void
hicn_pcs_cs_update (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		    hicn_pcs_entry_t * old_entry, hicn_pcs_entry_t * entry, hicn_hash_node_t * node)
{
  hicn_cs_policy_t *policy_state;
  hicn_cs_policy_vft_t *policy_vft;

  dpo_id_t *face_dpo = (dpo_id_t *) & (old_entry->u.cs.cs_rxface);
  policy_state = &pitcs->policy_state;
  policy_vft = &pitcs->policy_vft;

  if (face_dpo->dpoi_type == hicn_face_ip_type)
    {
      hicn_face_t *face = hicn_dpoi_get_from_idx (face_dpo->dpoi_index);
      if (face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD)
	{
	  hicn_face_prod_t *prod_face = (hicn_face_prod_t *) face->data;
	  policy_state = &prod_face->policy;
	  policy_vft = &prod_face->policy_vft;
	}
    }

  if (dpo_cmp(&entry->u.cs.cs_rxface, &old_entry->u.cs.cs_rxface) !=0)
    {
      /* Dequeue content from the old queue */
      policy_vft->hicn_cs_dequeue(pitcs, node, old_entry, policy_state);

      dpo_copy(&old_entry->u.cs.cs_rxface, &entry->u.cs.cs_rxface);
      face_dpo = (dpo_id_t *) & (old_entry->u.cs.cs_rxface);
      policy_state = &pitcs->policy_state;
      policy_vft = &pitcs->policy_vft;

      if (face_dpo->dpoi_type == hicn_face_ip_type)
        {
          hicn_face_t *face = hicn_dpoi_get_from_idx (face_dpo->dpoi_index);
          if (face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD)
            {
              hicn_face_prod_t *prod_face = (hicn_face_prod_t *) face->data;
              policy_state = &prod_face->policy;
              policy_vft = &prod_face->policy_vft;
            }
        }

      policy_vft->hicn_cs_insert (pitcs, node, old_entry, policy_state);

      if (policy_state->count > policy_state->max)
        {
          hicn_hash_node_t *node;
          hicn_pcs_entry_t *pcs_entry;
          hicn_hash_entry_t *hash_entry;
          policy_vft->hicn_cs_delete_get (pitcs, policy_state,
                                          &node, &pcs_entry, &hash_entry);

          /*
           * We don't have to decrease the lock (therefore we cannot
           * use hicn_pcs_cs_delete function)
           */
          policy_vft->hicn_cs_dequeue (pitcs, node, pcs_entry, policy_state);

          hicn_cs_delete_trimmed (pitcs, &pcs_entry, hash_entry, &node, vm);

          /* Update the global CS counter */
          pitcs->pcs_cs_count--;
        }
    }
  else
    /* Update the CS LRU, moving this item to the head */
    policy_vft->hicn_cs_update (pitcs, node, old_entry, policy_state);
}

always_inline void
hicn_pcs_cs_delete (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		    hicn_pcs_entry_t ** pcs_entryp, hicn_hash_node_t ** nodep,
		    hicn_hash_entry_t * hash_entry,
		    const hicn_dpo_vft_t * dpo_vft, dpo_id_t * hicn_dpo_id)
{
  if (!(hash_entry->he_flags & HICN_HASH_ENTRY_FLAG_DELETED))
    {
      hicn_cs_policy_t *policy_state;
      hicn_cs_policy_vft_t *policy_vft;

      dpo_id_t *face_dpo = (dpo_id_t *) & ((*pcs_entryp)->u.cs.cs_rxface);
      policy_state = &pitcs->policy_state;
      policy_vft = &pitcs->policy_vft;

      if (face_dpo->dpoi_type == hicn_face_ip_type)
	{
	  hicn_face_t *face = hicn_dpoi_get_from_idx (face_dpo->dpoi_index);
	  if (face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD)
	    {
	      hicn_face_prod_t *prod_face = (hicn_face_prod_t *) face->data;
	      policy_state = &prod_face->policy;
	      policy_vft = &prod_face->policy_vft;
	    }
	}
      policy_vft->hicn_cs_dequeue (pitcs, (*nodep), (*pcs_entryp),
				   policy_state);

      /* Update the global CS counter */
      pitcs->pcs_cs_count--;
    }

  /* A data could have been inserted in the CS through a push. In this case locks == 0 */
  hash_entry->locks--;
  if (hash_entry->locks == 0)
    {
      hicn_pcs_delete_internal
	(pitcs, pcs_entryp, hash_entry, nodep, vm, dpo_vft, hicn_dpo_id);
    }
  else
    {
      hash_entry->he_flags |= HICN_HASH_ENTRY_FLAG_DELETED;
    }
}

always_inline int
hicn_pcs_cs_insert (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		    hicn_pcs_entry_t * entry, hicn_hash_node_t * node,
		    hicn_hash_entry_t ** hash_entry, u64 hashval,
		    u32 * node_id, index_t * dpo_ctx_id, u8 * vft_id, u8 * is_cs,
		    u8 * hash_entry_id, u32 * bucket_id,
		    u8 * bucket_is_overflow)
{
  ASSERT (entry == hicn_hashtb_node_data (node));

  int ret =
    hicn_hashtb_insert (pitcs->pcs_table, node, hash_entry, hashval, node_id,
			dpo_ctx_id, vft_id, is_cs, hash_entry_id, bucket_id,
			bucket_is_overflow);

  if (PREDICT_TRUE (ret == HICN_ERROR_NONE))
    {
      /* Mark the entry as a CS entry */
      node->hn_flags |= HICN_HASH_NODE_CS_FLAGS;
      entry->shared.entry_flags |= HICN_PCS_ENTRY_CS_FLAG;
      (*hash_entry)->he_flags |= HICN_HASH_ENTRY_FLAG_CS_ENTRY;

      hicn_cs_policy_t *policy_state;
      hicn_cs_policy_vft_t *policy_vft;

      dpo_id_t *face_dpo = (dpo_id_t *) & (entry->u.cs.cs_rxface);
      policy_state = &pitcs->policy_state;
      policy_vft = &pitcs->policy_vft;

      if (face_dpo->dpoi_type == hicn_face_ip_type)
	{
	  hicn_face_t *face = hicn_dpoi_get_from_idx (face_dpo->dpoi_index);
	  if (face->shared.flags & HICN_FACE_FLAGS_APPFACE_PROD)
	    {
	      hicn_face_prod_t *prod_face = (hicn_face_prod_t *) face->data;
	      policy_state = &prod_face->policy;
	      policy_vft = &prod_face->policy_vft;
	    }
	}
      policy_vft->hicn_cs_insert (pitcs, node, entry, policy_state);
      pitcs->pcs_cs_count++;

      if (policy_state->count > policy_state->max)
	{
	  hicn_hash_node_t *node;
	  hicn_pcs_entry_t *pcs_entry;
	  hicn_hash_entry_t *hash_entry;
	  policy_vft->hicn_cs_delete_get (pitcs, policy_state,
					  &node, &pcs_entry, &hash_entry);

          /*
           * We don't have to decrease the lock (therefore we cannot
           * use hicn_pcs_cs_delete function)
           */
          policy_vft->hicn_cs_dequeue (pitcs, node, pcs_entry, policy_state);

          hicn_cs_delete_trimmed (pitcs, &pcs_entry, hash_entry, &node, vm);

          /* Update the global CS counter */
          pitcs->pcs_cs_count--;
	}
    }
  return ret;
}

/*
 * Insert CS entry into the hashtable The main purpose of this wrapper is
 * helping maintain the per-PIT stats.
 */
always_inline int
hicn_pcs_cs_insert_update (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
			   hicn_pcs_entry_t * entry, hicn_hash_node_t * node,
			   hicn_hash_entry_t ** hash_entry, u64 hashval,
			   u32 * node_id, index_t * dpo_ctx_id, u8 * vft_id,
			   u8 * is_cs, u8 * hash_entry_id, u32 * bucket_id,
			   u8 * bucket_is_overflow, dpo_id_t * inface)
{
  int ret;

  ASSERT (entry == hicn_hashtb_node_data (node));

  entry->u.cs.cs_rxface = *inface;
  ret =
    hicn_pcs_cs_insert (vm, pitcs, entry, node, hash_entry, hashval, node_id,
			dpo_ctx_id, vft_id, is_cs, hash_entry_id, bucket_id,
			bucket_is_overflow);

  /* A content already exists in CS with the same name */
  if (ret == HICN_ERROR_HASHTB_EXIST && *is_cs)
    {
      /* Update the entry */
      hicn_hash_node_t *existing_node =
	hicn_hashtb_node_from_idx (pitcs->pcs_table, *node_id);
      hicn_pcs_entry_t *pitp = hicn_pit_get_data (existing_node);

      /* Free associated packet buffer and update counter */
      pitcs->pcs_cs_dealloc++;
      vlib_buffer_free_one (vm, pitp->u.cs.cs_pkt_buf);

      pitp->shared.create_time = entry->shared.create_time;
      pitp->shared.expire_time = entry->shared.expire_time;
      pitp->u.cs.cs_pkt_buf = entry->u.cs.cs_pkt_buf;

      hicn_pcs_cs_update (vm, pitcs, pitp, entry, existing_node);
    }

  return (ret);
}

/*
 * Insert PIT entry into the hashtable The main purpose of this wrapper is
 * helping maintain the per-PIT stats.
 */
always_inline int
hicn_pcs_pit_insert (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t * entry,
		     hicn_hash_node_t * node, hicn_hash_entry_t ** hash_entry,
		     u64 hashval, u32 * node_id, index_t * dpo_ctx_id, u8 * vft_id,
		     u8 * is_cs, u8 * hash_entry_id, u32 * bucket_id,
		     u8 * bucket_is_overflow)
{
  ASSERT (entry == hicn_hashtb_node_data (node));

  int ret =
    hicn_hashtb_insert (pitcs->pcs_table, node, hash_entry, hashval, node_id,
			dpo_ctx_id, vft_id, is_cs, hash_entry_id, bucket_id,
			bucket_is_overflow);

  if (PREDICT_TRUE (ret == HICN_ERROR_NONE))
    pitcs->pcs_pit_count++;

  return ret;
}

always_inline void
hicn_pcs_pit_delete (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t ** pcs_entryp,
		     hicn_hash_node_t ** node, vlib_main_t * vm,
		     hicn_hash_entry_t * hash_entry,
		     const hicn_dpo_vft_t * dpo_vft, dpo_id_t * hicn_dpo_id)
{
  hash_entry->locks--;
  if (hash_entry->locks == 0)
    {
      pitcs->pcs_pit_count--;
      hicn_pcs_delete_internal
	(pitcs, pcs_entryp, hash_entry, node, vm, dpo_vft, hicn_dpo_id);
    }
  else
    {
      hash_entry->he_flags |= HICN_HASH_ENTRY_FLAG_DELETED;
    }
}


/* Generic functions for PIT/CS */

/*
 * Insert PIT/CS entry into the hashtable The main purpose of this wrapper is
 * helping maintain the per-PIT stats.
 */
always_inline int
hicn_pcs_insert (vlib_main_t * vm, hicn_pit_cs_t * pitcs,
		 hicn_pcs_entry_t * entry, hicn_hash_node_t * node,
		 hicn_hash_entry_t ** hash_entry, u64 hashval, u32 * node_id,
		 index_t * dpo_ctx_id, u8 * vft_id, u8 * is_cs, u8 * hash_entry_id,
		 u32 * bucket_id, u8 * bucket_is_overflow)
{
  int ret;

  if ((*hash_entry)->he_flags & HICN_HASH_ENTRY_FLAG_CS_ENTRY)
    {
      ret =
	hicn_pcs_cs_insert (vm, pitcs, entry, node, hash_entry, hashval,
			    node_id, dpo_ctx_id, vft_id, is_cs, hash_entry_id,
			    bucket_id, bucket_is_overflow);
    }
  else
    {
      ret =
	hicn_pcs_pit_insert (pitcs, entry, node, hash_entry, hashval, node_id,
			     dpo_ctx_id, vft_id, is_cs, hash_entry_id,
			     bucket_id, bucket_is_overflow);
    }

  return (ret);
}


/*
 * Delete entry if there are no pending lock on the entry, otherwise mark it
 * as to delete.
 */
always_inline void
hicn_pcs_delete (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t ** pcs_entryp,
		 hicn_hash_node_t ** nodep, vlib_main_t * vm,
		 hicn_hash_entry_t * hash_entry,
		 const hicn_dpo_vft_t * dpo_vft, dpo_id_t * hicn_dpo_id)
{
  /*
   * If the entry has already been marked as deleted, it has already
   * been dequeue
   */
  if (hash_entry->he_flags & HICN_HASH_ENTRY_FLAG_CS_ENTRY)
    {
      hicn_pcs_cs_delete (vm, pitcs, pcs_entryp, nodep, hash_entry,
			  dpo_vft, hicn_dpo_id);
    }
  else
    {
      hicn_pcs_pit_delete (pitcs, pcs_entryp, nodep, vm,
			   hash_entry, dpo_vft, hicn_dpo_id);
    }
}

/*
 * Remove a lock in the entry and delete it if there are no pending lock and
 * the entry is marked as to be deleted
 */
always_inline void
hicn_pcs_remove_lock (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t ** pcs_entryp,
		      hicn_hash_node_t ** node, vlib_main_t * vm,
		      hicn_hash_entry_t * hash_entry,
		      const hicn_dpo_vft_t * dpo_vft, dpo_id_t * hicn_dpo_id)
{
  hash_entry->locks--;
  if (hash_entry->locks == 0
      && (hash_entry->he_flags & HICN_HASH_ENTRY_FLAG_DELETED))
    {
      hicn_pcs_delete_internal
	(pitcs, pcs_entryp, hash_entry, node, vm, dpo_vft, hicn_dpo_id);
    }
}

/*
 * Delete entry which has already been bulk-removed from lru list
 */
always_inline void
hicn_cs_delete_trimmed (hicn_pit_cs_t * pitcs, hicn_pcs_entry_t ** pcs_entryp,
			hicn_hash_entry_t * hash_entry,
			hicn_hash_node_t ** node, vlib_main_t * vm)
{


  if (hash_entry->locks == 0)
    {
      const hicn_dpo_vft_t *dpo_vft = hicn_dpo_get_vft (hash_entry->vft_id);
      dpo_id_t hicn_dpo_id =
	{ dpo_vft->hicn_dpo_get_type (), 0, 0, hash_entry->dpo_ctx_id };

      hicn_pcs_delete_internal
	(pitcs, pcs_entryp, hash_entry, node, vm, dpo_vft, &hicn_dpo_id);
    }
  else
    {
      hash_entry->he_flags |= HICN_HASH_ENTRY_FLAG_DELETED;
    }
}

/*
 * wrappable counter math (assumed uint16_t): return sum of addends
 */
always_inline u16
hicn_infra_seq16_sum (u16 addend1, u16 addend2)
{
  return (addend1 + addend2);
}

/*
 * for comparing wrapping numbers, return lt,eq,gt 0 for a lt,eq,gt b
 */
always_inline int
hicn_infra_seq16_cmp (u16 a, u16 b)
{
  return ((int16_t) (a - b));
}

/*
 * below are wrappers for lt, le, gt, ge seq16 comparators
 */
always_inline int
hicn_infra_seq16_lt (u16 a, u16 b)
{
  return (hicn_infra_seq16_cmp (a, b) < 0);
}

always_inline int
hicn_infra_seq16_le (u16 a, u16 b)
{
  return (hicn_infra_seq16_cmp (a, b) <= 0);
}

always_inline int
hicn_infra_seq16_gt (u16 a, u16 b)
{
  return (hicn_infra_seq16_cmp (a, b) > 0);
}

always_inline int
hicn_infra_seq16_ge (u16 a, u16 b)
{
  return (hicn_infra_seq16_cmp (a, b) >= 0);
}


extern u16 hicn_infra_fast_timer;	/* Counts at 1 second intervals */
extern u16 hicn_infra_slow_timer;	/* Counts at 1 minute intervals */

/*
 * Utilities to convert lifetime into expiry time based on compressed clock,
 * suitable for the opportunistic hashtable entry timeout processing.
 */

//convert time in msec to time in clicks
always_inline u16
hicn_infra_ms2clicks (u64 time_ms, u64 ms_per_click)
{
  f64 time_clicks =
    ((f64) (time_ms + ms_per_click - 1)) / ((f64) ms_per_click);
  return ((u16) time_clicks);
}

always_inline u16
hicn_infra_get_fast_exp_time (u64 lifetime_ms)
{
  u16 lifetime_clicks =
    hicn_infra_ms2clicks (lifetime_ms, HICN_INFRA_FAST_TIMER_MSECS);
  return (hicn_infra_seq16_sum (hicn_infra_fast_timer, lifetime_clicks));
}

always_inline u16
hicn_infra_get_slow_exp_time (u64 lifetime_ms)
{
  u16 lifetime_clicks =
    hicn_infra_ms2clicks (lifetime_ms, HICN_INFRA_SLOW_TIMER_MSECS);
  return (hicn_infra_seq16_sum (hicn_infra_slow_timer, lifetime_clicks));
}

#endif /* // __HICN_PCS_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
