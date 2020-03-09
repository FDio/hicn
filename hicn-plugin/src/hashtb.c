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

#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vppinfra/pool.h>

#include "pcs.h"
#include "hashtb.h"
#include "parser.h"
#include "error.h"

/* return dvd/dvr, rounded up (intended for integer values) */
#define    CEIL(dvd, dvr)                       \
  ({                                            \
    __typeof__ (dvd) _dvd = (dvd);              \
    __typeof__ (dvr) _dvr = (dvr);              \
    (_dvd + _dvr - 1)/_dvr;                     \
  })

#ifndef ALIGN8
#define ALIGN8(p) (((p) + 0x7) & ~(0x7))
#endif

#ifndef ALIGNPTR8
#define ALIGNPTR8(p) ((void *)(((u8 * )(p) + 0x7) & ~(0x7)))
#endif

#ifndef ALIGN64
#define ALIGN64(p) (((p) + 0x3f) & ~(0x3f))
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif


/*
 * Offset to aligned start of additional data (PIT/CS, FIB) embedded in each
 * node.
 */
u32 ht_node_data_offset_aligned;

/* Some support for posix vs vpp mem management */
#define MEM_ALLOC(x) clib_mem_alloc_aligned((x), 8)
#define MEM_FREE(p) clib_mem_free((p))

/*
 * Internal utilities
 */

/* Allocate an overflow bucket */
static hicn_hash_bucket_t *
alloc_overflow_bucket (hicn_hashtb_h h)
{
  hicn_hash_bucket_t *newbkt = NULL;

  if (h->ht_overflow_buckets_used < h->ht_overflow_bucket_count)
    {
      pool_get_aligned (h->ht_overflow_buckets, newbkt, 8);

      if (newbkt)
	{
	  h->ht_overflow_buckets_used++;
	}
    }
  return (newbkt);
}

/* Free an overflow bucket; clear caller's pointer */
static void
free_overflow_bucket (hicn_hashtb_h h, hicn_hash_bucket_t ** pb)
{
  hicn_hash_bucket_t *bkt = *pb;

  ASSERT (h->ht_overflow_buckets_used > 0);

  pool_put (h->ht_overflow_buckets, bkt);
  h->ht_overflow_buckets_used--;
  *pb = NULL;
}

/*
 * Init, allocate a new hashtable
 */
int
hicn_hashtb_alloc (hicn_hashtb_h * ph, u32 max_elems, size_t app_data_size)
{
  int ret = HICN_ERROR_NONE;
  hicn_hashtb_h h = NULL;
  u32 count;
  u32 total_buckets;
  size_t sz;
  hicn_hash_node_t *nodep;
  hicn_hash_bucket_t *bucket;

  if (ph == NULL)
    {
      ret = HICN_ERROR_HASHTB_INVAL;
      goto done;
    }
  if (max_elems < HICN_HASHTB_MIN_ENTRIES ||
      max_elems > HICN_HASHTB_MAX_ENTRIES)
    {
      goto done;
    }
  /* Allocate and init main hashtable struct */
  h = MEM_ALLOC (sizeof (hicn_hashtb_t));
  if (h == NULL)
    {
      ret = HICN_ERROR_HASHTB_NOMEM;
      goto done;
    }
  memset (h, 0, sizeof (hicn_hashtb_t));

  /* Compute main table bucket (row) count and size, and allocate */

  /* Consider the last entry as used for containing the overflow bucket */
  total_buckets = CEIL (max_elems, HICN_HASHTB_BUCKET_ENTRIES - 1);
  count = ALIGN8 (CEIL (total_buckets, HICN_HASHTB_FILL_FACTOR));

  h->ht_bucket_count = count;

  /* We _really_ expect to have buckets aligned on cache lines ... */
  sz = sizeof (hicn_hash_bucket_t);
  assert (sz == ALIGN64 (sz));

  h->ht_buckets = MEM_ALLOC (count * sz);
  if (h->ht_buckets == NULL)
    {
      ret = HICN_ERROR_HASHTB_NOMEM;
      goto done;
    }
  memset (h->ht_buckets, 0, count * sz);

  /*
   * First time through, compute offset to aligned extra data start in
   * each node struct it's crucial that both the node struct (that the
   * base hashtable uses) and the extra data area (that's also probably
   * a struct) are aligned.
   */
  if (ht_node_data_offset_aligned == 0)
    {
      count = STRUCT_OFFSET_OF (hicn_hash_node_t, hn_data);
      ht_node_data_offset_aligned = ALIGN8 (count);
    }
  //check app struct fits into space provided(HICN_HASH_NODE_APP_DATA_SIZE)
  u32 ht_node_data_size;
  ht_node_data_size = sizeof (hicn_hash_node_t) - ht_node_data_offset_aligned;
  if (app_data_size > ht_node_data_size)
    {
      clib_error
	("hicn hashtable: fatal error: requested app data size(%u) > hashtb node's configured bytes available(%u), sizeof(hicn_shared_t)=%u, sizeof(hicn_pit_entry_t)=%u, sizeof(hicn_cs_entry_t)=%u",
	 app_data_size, ht_node_data_size, sizeof (hicn_pcs_shared_t),
	 sizeof (hicn_pit_entry_t), sizeof (hicn_cs_entry_t));
    }
  /*
   * Compute entry node count and size, allocate Allocate/'Hide' the
   * zero-th node so can use zero as an 'empty' value
   */
  pool_alloc_aligned (h->ht_nodes, max_elems, 8);
  if (h->ht_nodes == NULL)
    {
      ret = HICN_ERROR_HASHTB_NOMEM;
      goto done;
    }
  pool_get_aligned (h->ht_nodes, nodep, 8);
  //alloc node 0
  nodep = nodep;		/* Silence 'not used' warning */

  h->ht_node_count = max_elems;
  h->ht_nodes_used = 1;

  /*
   * Compute overflow bucket count and size, allocate
   */
  //count = ALIGN8(CEIL(max_elems, HICN_HASHTB_OVERFLOW_FRACTION));
  count = ALIGN8 (total_buckets - h->ht_bucket_count);

  pool_alloc_aligned (h->ht_overflow_buckets, count, 8);
  if (h->ht_overflow_buckets == NULL)
    {
      ret = HICN_ERROR_HASHTB_NOMEM;
      goto done;
    }
  /* 'Hide' the zero-th node so we can use zero as an 'empty' value */
  pool_get_aligned (h->ht_overflow_buckets, bucket, 8);
  bucket = bucket;		/* Silence 'not used' warning */

  h->ht_overflow_bucket_count = count;
  h->ht_overflow_buckets_used = 1;

done:

  if (h)
    {
      if ((ret == HICN_ERROR_NONE) && ph)
	{
	  *ph = h;
	}
      else
	{
	  hicn_hashtb_free (&h);
	}
    }
  return (ret);
}

/*
 * Free, de-allocate a hashtable
 */
int
hicn_hashtb_free (hicn_hashtb_h * ph)
{
  int ret = 0;

  if (ph)
    {
      if ((*ph)->ht_nodes)
	{
	  pool_free ((*ph)->ht_nodes);
	  (*ph)->ht_nodes = 0;
	}
      if ((*ph)->ht_overflow_buckets)
	{
	  pool_free ((*ph)->ht_overflow_buckets);
	  (*ph)->ht_overflow_buckets = 0;
	}
      if ((*ph)->ht_buckets)
	{
	  MEM_FREE ((*ph)->ht_buckets);
	  (*ph)->ht_buckets = 0;
	}
      MEM_FREE (*ph);

      *ph = NULL;
    }
  return (ret);
}



/*
 * Basic api to lookup a specific hash+key tuple. This does the entire lookup
 * operation, retrieving node structs and comparing keys, so it's not
 * optimized for prefetching or high performance.
 *
 * Returns zero and mails back a node on success, errno otherwise.
 */
int
hicn_hashtb_lookup_node (hicn_hashtb_h h, const u8 * key,
			 u32 keylen, u64 hashval, u8 is_data,
			 u32 * node_id, index_t * dpo_ctx_id, u8 * vft_id,
			 u8 * is_cs, u8 * hash_entry_id, u32 * bucket_id,
			 u8 * bucket_is_overflow)
{
  return (hicn_hashtb_lookup_node_ex
	  (h, key, keylen, hashval, is_data, FALSE /* deleted nodes */ ,
	   node_id,
	   dpo_ctx_id, vft_id, is_cs, hash_entry_id, bucket_id,
	   bucket_is_overflow));
}

/*
 * Extended api to lookup a specific hash+key tuple. The implementation
 * allows the caller to locate nodes that are marked for deletion, which is
 * part of some hashtable applications, such as the FIB.
 *
 * This does the entire lookup operation, retrieving node structs and comparing
 * keys, so it's not optimized for prefetching or high performance.
 *
 * Returns zero and mails back a node on success, errno otherwise.
 */
int
hicn_hashtb_lookup_node_ex (hicn_hashtb_h h, const u8 * key,
			    u32 keylen, u64 hashval, u8 is_data,
			    int include_deleted_p, u32 * node_id,
			    index_t * dpo_ctx_id, u8 * vft_id, u8 * is_cs,
			    u8 * hash_entry_id, u32 * bucket_id,
			    u8 * bucket_is_overflow)
{
  int i, ret = HICN_ERROR_HASHTB_HASH_NOT_FOUND;
  int found_p = FALSE;
  u32 bidx;
  hicn_hash_bucket_t *bucket;
  u32 current_bucket_id = ~0;

  /*
   * Use some bits of the low half of the hash to locate a row/bucket
   * in the table
   */
  current_bucket_id = bidx = (hashval & (h->ht_bucket_count - 1));

  bucket = h->ht_buckets + bidx;

  *bucket_is_overflow = 0;
  /* Check the entries in the bucket for matching hash value */

loop_buckets:

  for (i = 0; i < HICN_HASHTB_BUCKET_ENTRIES && !found_p; i++)
    {
      /*
       * If an entry is marked for deletion, ignore it unless the
       * caller explicitly wants these nodes.
       */
      if (bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_DELETED)
	{
	  if (!include_deleted_p)
	    {
	      continue;
	    }
	}
      if (bucket->hb_entries[i].he_msb64 == hashval)
	{
	  /*
	   * Found a candidate - must retrieve the actual node
	   * and check the key.
	   */
	  *node_id = bucket->hb_entries[i].he_node;
	  *dpo_ctx_id = bucket->hb_entries[i].dpo_ctx_id;
	  *vft_id = bucket->hb_entries[i].vft_id;
	  *is_cs =
	    bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_CS_ENTRY;
	  *hash_entry_id = i;
	  *bucket_id = current_bucket_id;
	  /*
	   * If we are doing lookup for a data, do not take a
	   * lock in case of a hit with a CS entry
	   */
	  if (!(is_data && *is_cs))
	    {
	      bucket->hb_entries[i].locks++;
	    }
	  found_p = TRUE;
	  ret = HICN_ERROR_NONE;
	  goto done;
	}
    }

  /*
   * Be prepared to continue to an overflow bucket if necessary. We
   * only expect the last entry in a bucket to refer to an overflow
   * bucket...
   */
  i = HICN_HASHTB_BUCKET_ENTRIES - 1;
  if (bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_OVERFLOW)
    {
      current_bucket_id = bucket->hb_entries[i].he_node;
      bucket = pool_elt_at_index (h->ht_overflow_buckets,
				  bucket->hb_entries[i].he_node);
      *bucket_is_overflow = 1;
      goto loop_buckets;
    }
done:

  return (ret);
}

/**
 * This function allows to split the hash verification from the comparison of
 * the entire key. Useful to exploit prefertching.
 * return 1 if equals, 0 otherwise
 */
int
hicn_node_compare (const u8 * key, u32 keylen, hicn_hash_node_t * node)
{

  int ret = 0;

  if (key && keylen == node->hn_keysize)
    {
      ret = (memcmp (key, node->hn_key.ks.key, keylen) == 0);
    }
  return ret;
}

/*
 * Utility to init a new entry in a hashtable bucket/row. We use this to add
 * new a node+hash, and to clear out an entry during removal.
 */
void
hicn_hashtb_init_entry (hicn_hash_entry_t * entry, u32 nodeidx,
			u64 hashval, u32 locks)
{
  entry->he_msb64 = hashval;
  entry->he_node = nodeidx;

  /* Clear out some other fields in the entry */
  entry->he_flags = 0;
  entry->locks = locks;
  entry->vft_id = 0;
  entry->dpo_ctx_id = 0;
}

/*
 * Insert a node into the hashtable. We expect the caller has a) computed the
 * hash value to use, b) initialized the node with the hash and key info, and
 * c) filled in its app-specific data portion of the node.
 */

int
hicn_hashtb_insert (hicn_hashtb_h h, hicn_hash_node_t * node,
		    hicn_hash_entry_t ** hash_entry, u64 hash,
		    u32 * node_id,
		    index_t * dpo_ctx_id, u8 * vft_id, u8 * is_cs,
		    u8 * hash_entry_id, u32 * bucket_id,
		    u8 * bucket_is_overflow)
{
  int i, ret = HICN_ERROR_HASHTB_INVAL;
  u32 bidx;
  hicn_hash_bucket_t *bucket, *newbkt;
  int use_seven;
  u32 current_bucket_id = ~0;
  int is_overflow = 0;

  *hash_entry = NULL;

  if (h == NULL)
    {
      goto done;
    }
  /*
   * Use some bits of the low half of the hash to locate a row/bucket
   * in the table
   */
  current_bucket_id = bidx = (hash & (h->ht_bucket_count - 1));

  bucket = h->ht_buckets + bidx;

  use_seven = (h->ht_flags & HICN_HASHTB_FLAG_USE_SEVEN);

  /* Locate a free entry slot in the bucket */

loop_buckets:

  for (i = 0; i < HICN_HASHTB_BUCKET_ENTRIES; i++)
    {

      /*
       * If an entry is marked for deletion, ignore it
       */
      if (bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_DELETED)
	{
	  continue;
	}
      /*
       * Be sure that we are not inserting the same entry twice
       */
      if (bucket->hb_entries[i].he_msb64 == hash)
	{
	  /*
	   * We hit an existing pit entry. increase lock.
	   */

	  *node_id = bucket->hb_entries[i].he_node;
	  *dpo_ctx_id = bucket->hb_entries[i].dpo_ctx_id;
	  *vft_id = bucket->hb_entries[i].vft_id;
	  *is_cs =
	    bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_CS_ENTRY;
	  *hash_entry_id = i;
	  *bucket_id = current_bucket_id;
	  *hash_entry = &(bucket->hb_entries[i]);
	  /*
	   * If we are doing lookup for a data, do not take a
	   * lock in case of a hit with a CS entry
	   */
          if (!(*is_cs))
            bucket->hb_entries[i].locks++;
	  *bucket_is_overflow = is_overflow;
	  ret = HICN_ERROR_HASHTB_EXIST;
	  goto done;
	}
      if ((bucket->hb_entries[i].he_msb64 == 0LL) &&
	  (bucket->hb_entries[i].he_node == 0))
	{
	  /* Found a candidate -- fill it in */

	  /*
	   * Special case if the application asked not to use
	   * the last entry in each bucket.
	   */
	  if ((i != (HICN_HASHTB_BUCKET_ENTRIES - 1)) || use_seven)
	    {
	      hicn_hashtb_init_entry (&(bucket->hb_entries[i]),
				      NODE_IDX_FROM_NODE (node, h), hash, 0);

	      *hash_entry = &(bucket->hb_entries[i]);

	      node->bucket_id = current_bucket_id;
	      node->entry_idx = i;
	      (*hash_entry)->vft_id = *vft_id;
	      (*hash_entry)->dpo_ctx_id = *dpo_ctx_id;
	      if (is_overflow)
		node->hn_flags |= HICN_HASH_NODE_OVERFLOW_BUCKET;

	      ret = HICN_ERROR_NONE;
	      goto done;
	    }
	}
    }
  /*
   * Be prepared to continue to an overflow bucket if necessary, or to
   * add a new overflow bucket. We only expect the last entry in a
   * bucket to refer to an overflow bucket...
   */
  i = HICN_HASHTB_BUCKET_ENTRIES - 1;
  if (bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_OVERFLOW)
    {
      /* Existing overflow bucket - re-start the search loop */
      current_bucket_id = bucket->hb_entries[i].he_node;
      bucket = pool_elt_at_index (h->ht_overflow_buckets, current_bucket_id);
      is_overflow = 1;
      goto loop_buckets;

    }
  else
    {
      /*
       * Overflow - reached the end of a bucket without finding a
       * free entry slot. Need to allocate an overflow bucket, and
       * connect it to this bucket.
       */
      newbkt = alloc_overflow_bucket (h);
      if (newbkt == NULL)
	{
	  ret = HICN_ERROR_HASHTB_NOMEM;
	  goto done;
	}
      /*
       * We're touching some more bytes than we absolutely have to
       * here, but ... that seems ok.
       */
      memset (newbkt, 0, sizeof (hicn_hash_bucket_t));

      if (use_seven)
	{
	  /*
	   * Copy existing entry into new bucket - we really
	   * expect these to be properly aligned so they can be
	   * treated as int.
	   */
	  memcpy (&(newbkt->hb_entries[0]),
		  &(bucket->hb_entries[i]), sizeof (hicn_hash_entry_t));

	  /* Update bucket id and entry_idx on the hash node */
	  hicn_hash_node_t *node =
	    pool_elt_at_index (h->ht_nodes, newbkt->hb_entries[0].he_node);
	  node->bucket_id = (newbkt - h->ht_overflow_buckets);
	  node->entry_idx = 0;
	  node->hn_flags |= HICN_HASH_NODE_OVERFLOW_BUCKET;

	}
      /*
       * Connect original bucket to the index of the new overflow
       * bucket
       */
      bucket->hb_entries[i].he_flags |= HICN_HASH_ENTRY_FLAG_OVERFLOW;
      bucket->hb_entries[i].he_node = (newbkt - h->ht_overflow_buckets);

      /* Add new entry to new overflow bucket */
      bucket = newbkt;

      /*
       * Use entry [1] in the new bucket _if_ we just copied into
       * entry [zero] above.
       */
      if (use_seven)
	{

	  hicn_hashtb_init_entry (&(bucket->hb_entries[1]),
				  NODE_IDX_FROM_NODE (node, h), hash, 0);
	  *hash_entry = &(bucket->hb_entries[1]);

	  node->bucket_id = (newbkt - h->ht_overflow_buckets);
	  node->entry_idx = 1;
	  node->hn_flags |= HICN_HASH_NODE_OVERFLOW_BUCKET;
	  (*hash_entry)->vft_id = *vft_id;
	  (*hash_entry)->dpo_ctx_id = *dpo_ctx_id;
	}
      else
	{

	  hicn_hashtb_init_entry (&(bucket->hb_entries[0]),
				  NODE_IDX_FROM_NODE (node, h), hash, 0);
	  *hash_entry = &(bucket->hb_entries[0]);
	  node->bucket_id = (newbkt - h->ht_overflow_buckets);
	  node->entry_idx = 0;
	  node->hn_flags |= HICN_HASH_NODE_OVERFLOW_BUCKET;
	  (*hash_entry)->vft_id = *vft_id;
	  (*hash_entry)->dpo_ctx_id = *dpo_ctx_id;
	}
    }

  /* And we're done with the overflow bucket */
  ret = HICN_ERROR_NONE;

done:

  return (ret);
}

/*
 * Delete a node from a hashtable using the node itself, and delete/free the
 * node. Caller's pointer is cleared on success.
 */
void
hicn_hashtb_delete (hicn_hashtb_h h, hicn_hash_node_t ** pnode, u64 hashval)
{

  hicn_hashtb_remove_node (h, *pnode, hashval);
  hicn_hashtb_free_node (h, *pnode);
  *pnode = NULL;

}

/*
 * Delete an entry from a hashtable using the node itself. If the node was
 * stored in an overflow bucket, and the bucket is empty after freeing the
 * node, the bucket is freed as well.
 */
void
hicn_hashtb_remove_node (hicn_hashtb_h h, hicn_hash_node_t * node,
			 u64 hashval)
{
  int i, count;
  u32 bidx, overflow_p;
  hicn_hash_bucket_t *bucket, *parent;

  if ((h == NULL) || (node == NULL))
    {
      goto done;
    }
  if (node->hn_flags & HICN_HASH_NODE_OVERFLOW_BUCKET)
    bucket = pool_elt_at_index (h->ht_overflow_buckets, node->bucket_id);
  else
    {
      /*
       * Use some bits of the low half of the hash to locate a
       * row/bucket in the table
       */
      bidx = (hashval & (h->ht_bucket_count - 1));
      ASSERT (bidx == node->bucket_id);
      bucket = h->ht_buckets + node->bucket_id;
    }

  overflow_p = node->hn_flags & HICN_HASH_NODE_OVERFLOW_BUCKET;

  /* Clear out the entry. */
  hicn_hashtb_init_entry (&(bucket->hb_entries[node->entry_idx]), 0, 0LL, 0);

  if (!overflow_p)
    {
      /*
       * And we're done, in the easy case where we didn't change an
       * overflow bucket
       */
      goto done;
    }
  /*
   * The special case: if this is the last remaining entry in an
   * overflow bucket, liberate the bucket. That in turn has a special
   * case if this bucket is in the middle of a chain of overflow
   * buckets.
   *
   * Note that we're not trying aggressively (yet) to condense buckets at
   * every possible opportunity.
   */

  /*
   * Reset this flag; we'll set it again if this bucket links to
   * another
   */
  overflow_p = FALSE;

  for (i = 0, count = 0; i < HICN_HASHTB_BUCKET_ENTRIES; i++)
    {
      if (bucket->hb_entries[i].he_node != 0)
	{
	  count++;
	}
      if (i == (HICN_HASHTB_BUCKET_ENTRIES - 1) &&
	  (bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_OVERFLOW))
	{
	  count--;		/* Doesn't count as a 'real' entry */
	  overflow_p = TRUE;
	}
    }

  if (count > 0)
    {
      /* Still a (real) entry in the row */
      goto done;
    }
  /*
   * Need to locate the predecessor of 'bucket': start at the beginning
   * of the chain of buckets and move forward
   */
  bidx = (hashval & (h->ht_bucket_count - 1));

  for (parent = h->ht_buckets + bidx; parent != NULL;)
    {

      if ((parent->hb_entries[(HICN_HASHTB_BUCKET_ENTRIES - 1)].he_flags &
	   HICN_HASH_ENTRY_FLAG_OVERFLOW) == 0)
	{
	  parent = NULL;
	  break;
	}
      bidx = parent->hb_entries[(HICN_HASHTB_BUCKET_ENTRIES - 1)].he_node;

      if (pool_elt_at_index (h->ht_overflow_buckets, bidx) == bucket)
	{
	  /*
	   * Found the predecessor of 'bucket'. If 'bucket' has
	   * a successor, connect 'parent' to it, and take
	   * 'bucket out of the middle.
	   */
	  if (overflow_p)
	    {
	      parent->hb_entries[(HICN_HASHTB_BUCKET_ENTRIES - 1)].he_node =
		bucket->hb_entries[(HICN_HASHTB_BUCKET_ENTRIES - 1)].he_node;
	    }
	  else
	    {
	      /*
	       * Just clear the predecessor entry pointing
	       * at 'bucket'
	       */
	      hicn_hashtb_init_entry (&parent->hb_entries
				      [(HICN_HASHTB_BUCKET_ENTRIES - 1)], 0,
				      0LL, 0);
	    }

	  break;
	}
      /*
       * After the first iteration, 'parent' will be an overflow
       * bucket too
       */
      parent = pool_elt_at_index (h->ht_overflow_buckets, bidx);
    }

  /* We really expect to have found the predecessor */
  ASSERT (parent != NULL);

  /* And now, finally, we can put 'bucket' back on the free list */
  free_overflow_bucket (h, &bucket);

done:
  return;
}

/*
 * Prepare a hashtable node, supplying the key, and computed hash info.
 */
void
hicn_hashtb_init_node (hicn_hashtb_h h, hicn_hash_node_t * node,
		       const u8 * key, u32 keylen)
{
  assert (h != NULL);
  assert (node != NULL);
  assert (keylen <= HICN_PARAM_HICN_NAME_LEN_MAX);

  /* Init the node struct */
  node->hn_flags = HICN_HASH_NODE_FLAGS_DEFAULT;
  node->hn_keysize = 0;
  node->hn_keysize = keylen;
  memcpy (node->hn_key.ks.key, key, keylen);
  node->bucket_id = ~0;
  node->entry_idx = ~0;
}

/*
 * Release a hashtable node back to the free list when an entry is cleared
 */
void
hicn_hashtb_free_node (hicn_hashtb_h h, hicn_hash_node_t * node)
{
  ASSERT (h->ht_nodes_used > 0);

  /* Return 'node' to the free list */
  pool_put (h->ht_nodes, node);
  h->ht_nodes_used--;

}

/*
 * Walk a hashtable, iterating through the nodes, keeping context in 'ctx'.
 */
int
hicn_hashtb_next_node (hicn_hashtb_h h, hicn_hash_node_t ** pnode, u64 * ctx)
{
  int i, j, ret = HICN_ERROR_HASHTB_INVAL;
  u32 bidx, entry;
  hicn_hash_bucket_t *bucket;

  if ((h == NULL) || (pnode == NULL) || (ctx == NULL))
    {
      goto done;
    }
  /* Special-case for new iteration */
  if (*ctx == HICN_HASH_WALK_CTX_INITIAL)
    {
      bidx = 0;
      bucket = &h->ht_buckets[0];
      entry = 0;
      j = 0;
      i = 0;
      goto search_table;
    }
  /* Convert context to bucket and entry indices */
  bidx = *ctx & 0xffffffffLL;
  entry = *ctx >> 32;

  if (bidx >= h->ht_bucket_count)
    {
      ret = HICN_ERROR_HASHTB_HASH_NOT_FOUND;
      goto done;
    }
  bucket = h->ht_buckets + bidx;

  /* Init total index into entries (includes fixed bucket and overflow) */
  j = 0;

skip_processed_bucket_chunks:
  /*
   * Figure out where to resume the search for the next entry in the
   * table, by trying to find the last entry returned, from the cookie.
   * Loop walks one (regular or overflow) bucket chunk, label is used
   * for walking chain of chunks. Note that if there was a deletion or
   * an addition that created an overflow, iterator can skip entries or
   * return duplicate entries, for entries that are present from before
   * the walk starts until after it ends.
   */

  for (i = 0; i < HICN_HASHTB_BUCKET_ENTRIES; i++, j++)
    {
      if (j > entry)
	{
	  /*
	   * Start search for next here, use existing 'bucket'
	   * and 'i'
	   */
	  break;
	}
      /*
       * If an entry is marked for deletion, ignore it
       */
      if (bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_DELETED)
	{
	  continue;
	}
      /*
       * Be prepared to continue to an overflow bucket if
       * necessary. (We only expect the last entry in a bucket to
       * refer to an overflow bucket...)
       */
      if (i == (HICN_HASHTB_BUCKET_ENTRIES - 1))
	{
	  if (bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_OVERFLOW)
	    {
	      bucket = pool_elt_at_index (h->ht_overflow_buckets,
					  bucket->hb_entries[i].he_node);

	      /* Increment overall entry counter 'j' */
	      j++;

	      goto skip_processed_bucket_chunks;
	    }
	  /*
	   * end of row (end of fixed bucket plus any
	   * overflows)
	   */
	  i = 0;
	  j = 0;

	  bidx++;

	  /* Special case - we're at the end */
	  if (bidx >= h->ht_bucket_count)
	    {
	      ret = HICN_ERROR_HASHTB_HASH_NOT_FOUND;
	      goto done;
	    }
	  bucket = h->ht_buckets + bidx;
	  break;
	}
    }

search_table:

  /*
   * Now we're searching through the table for the next entry that's
   * set
   */

  for (; i < HICN_HASHTB_BUCKET_ENTRIES; i++, j++)
    {
      /*
       * If an entry is marked for deletion, ignore it
       */
      if (bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_DELETED)
	{
	  continue;
	}
      /* Is this entry set? */
      if (bucket->hb_entries[i].he_node != 0)
	{

	  /* Retrieve the node struct */
	  *pnode = pool_elt_at_index (h->ht_nodes,
				      bucket->hb_entries[i].he_node);

	  /*
	   * Set 'entry' as we exit, so we can update the
	   * cookie
	   */
	  entry = j;
	  ret = HICN_ERROR_NONE;
	  break;
	}
      /*
       * Be prepared to continue to an overflow bucket if
       * necessary. (We only expect the last entry in a bucket to
       * refer to an overflow bucket...)
       */
      if (i == (HICN_HASHTB_BUCKET_ENTRIES - 1))
	{
	  if (bucket->hb_entries[i].he_flags & HICN_HASH_ENTRY_FLAG_OVERFLOW)
	    {
	      bucket = pool_elt_at_index (h->ht_overflow_buckets,
					  bucket->hb_entries[i].he_node);
	      /*
	       * Reset per-bucket index 'i', here (not done
	       * in iterator)
	       */
	      i = 0;
	      /* Increment overall entry counter 'j' */
	      j++;

	      goto search_table;
	    }
	  else
	    {
	      /*
	       * Move to next bucket, resetting per-bucket
	       * and overall entry indexes
	       */
	      i = 0;
	      j = 0;

	      bidx++;

	      /* Special case - we're at the end */
	      if (bidx >= h->ht_bucket_count)
		{
		  ret = HICN_ERROR_HASHTB_HASH_NOT_FOUND;
		  goto done;
		}
	      bucket = h->ht_buckets + bidx;
	      goto search_table;
	    }
	}
    }

done:

  if (ret == HICN_ERROR_NONE)
    {
      /* Update context */
      *ctx = bidx;
      *ctx |= ((u64) entry << 32);
    }
  return (ret);
}

int
hicn_hashtb_key_to_buf (u8 ** vec_res, hicn_hashtb_h h,
			const hicn_hash_node_t * node)
{
  int ret = HICN_ERROR_NONE;
  u8 *vec = *vec_res;

  if (node->hn_keysize <= HICN_HASH_KEY_BYTES)
    {
      vec_add (vec, node->hn_key.ks.key, node->hn_keysize);
    }
  *vec_res = vec;
  return (ret);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
