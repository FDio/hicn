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

#ifndef __HICN_HASHTB_H__
#define __HICN_HASHTB_H__

#include <stdint.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>

#include "params.h"
#include "parser.h"
#include "error.h"

/* Handy abbreviations for success status, and for boolean values */
#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/*
 * Lookup is finding a hashtable record whose name matches the name being
 * looked up.  Most of the lookup work is based on the hash value of the two
 * names. Note that the intel cache line size is 64 bytes, and some platforms
 * load in 2 cache lines together. - first step is to match a record at the
 * bucket/slot level (htab has an array of htbucket_t/htbc_elmt, where each
 * bucket has 7 slots to hold indices for entries.) Matching at this level
 * implies - the hashes of the lookup name and the record map to the same
 * bucket - the high 32 bits of the hashes (slot bce_hash_msb32s) match. Read
 * cost (on the hash table size, i.e. ignoring reading the name being looked
 * up): - First step normally requires 1 cache line load to pull in the
 * 64-byte htbucket_t with the 7 element slot table holding the hash_msb32s.
 * - In the event (hopefully rare for a hash table with appropriate number of
 * buckets) that more than 7 elements hash to the same bucket, lookup may
 * well need to look not only at the static htbc_elmt_t but at the chain of
 * dynamically allocated htbc_elmt_t's linked to the static htbc_elmt_t,
 * where each of these holds slot entries for additional elements. - Before
 * reaching that point, it is initially required is to read in the hash table
 * record fields (ht_bucket_buf, htnode buf, etc) holding pointers to the
 * arrays, but these cache lines are common to all lookups so will likely
 * already be in the cache. - second step is to match at the record level
 * (htnode/htkb level) once a slot-level match happens. Matching at this
 * level implies the following match - the hash values (the full 64 bits vs.
 * bucket+32 msb, above) With siphash, two names hashing to the same 64-bit
 * value is quite rare. - the name which, on the hash table side, is stored
 * as a list of htkb_t (key buffers). [In some cases, the full name is not
 * compared, and a match is assumed based on hash value match. Read cost: -
 * htnode_t, in one cache line, holds hash value and index for the htkb at
 * the head of the key buffer list - each key buffer (htkb_t) is cache line
 * aligned/sized, and holds 60 bytes of the name and requires a cache line
 * read. Simplification is that a fib lookup requires 3 cache lines: - bucket
 * - htnode - single key buffer (for cases where a name comparision is done)
 *
 * Some hashtables (for which rare false positives are tolerable) store hash
 * values but no keys. (In ISM NDN forwarder, this was used for dcm_dpf: data
 * cache manager's dataplane filter, where speed was critical and very rare
 * false positives would be detected in the full dcm check.) - No key buffers
 * are used (or even allocated at hash table creation).
 */

#define HICN_HASH_INVALID_IDX  ~0
/*
 * for hicn_hashtb_next_node() iterator, this otherwise illegal context value
 * indicates first call of iteration. Note: must not be 0, which is a legal
 * context value.
 */
#define HICN_HASH_WALK_CTX_INITIAL (~((u64)0))

/*
 * Key memory allocation scheme.
 *
 * The key is the bytestring that a hashtable entry is storing, e.g. a fib
 * prefix or packet name. The hash of the name is used not just to pick the
 * bucket, but also as a surrogate for the actual key value.
 *
 * Client calls pass key/name as contiguous memory for lookup/add/delete but
 * hashable stores its copy of the key/name as a list of one or more hash_key
 * structs. - key memory is managed as a list of keys (cache line
 * sized/aligned buffers). - If (keysize < 128) then use key struct's full
 * 128 bytes - If not, first key struct is head of a linked list of elements
 * where the first bytes are used for the key and the last 4 bytes are the
 * index of the next entry (or an end marker). - key memory is generally the
 * single largest use of memory in the hash table, especially for PIT, as
 * names are bigger than node structs (which is also per name/entry).
 *
 */

/* Compute hash node index from node pointer */
#define NODE_IDX_FROM_NODE(p, h) \
  (u32)((p) - ((h)->ht_nodes))

#define HICN_HASH_KEY_BYTES   20

typedef struct
{
  struct
  {
    u8 key[HICN_HASH_KEY_BYTES];
  } ks;				/* Entire key in one block */
} hicn_hash_key_t;

/*
 * Ratio of extra key blocks to allocate, in case the embedded ones aren't
 * sufficient. This is the fraction of the number of entries allocated.
 */
#define HICN_HASHTB_KEY_RATIO 8

/*
 * hash node, used to store a hash table entry; indexed by an entry in a
 * bucket. the node contains an embedded key; long keys are stored as chains
 * of keys.
 *
 * The memory block for a node includes space for storing outgoing faces for
 * interests, additional memory located off the end of the htnode data structure.
 *
 */

/* Size this so that we can offer 64B aligned on 64-bits for storing outgoing
 * faces information
 */
#define HICN_HASH_NODE_APP_DATA_SIZE 64

/* How to align in the right way */
typedef struct __attribute__ ((packed)) hicn_hash_node_s
{
  /* Bucket id containing the corresponding hash entry. */
  u32 bucket_id;

  /* Hash entry index in the bucket */
  u32 entry_idx;

  /* Total size of the key */
  u16 hn_keysize;

  /* 1 byte of flags for application use */
  u8 hn_flags;

  u8 _hn_reserved1;		/* TBD, to align what follows back to
				 * 32 */

  hicn_hash_key_t hn_key;	/* Key value embedded in the node, may chain
				 * to more key buffers if necessary */

  /* 32B + HICN_HASH_NODE_APP_DATA_SIZE */
  /* Followed by app-specific data (fib or pit or cs entry, e.g.) */
  u8 hn_data[HICN_HASH_NODE_APP_DATA_SIZE];

} hicn_hash_node_t;

#define HICN_HASH_NODE_FLAGS_DEFAULT     0x00
#define HICN_HASH_NODE_CS_FLAGS          0x01
#define HICN_HASH_NODE_OVERFLOW_BUCKET   0x02

/*
 * hicn_hash_entry_t Structure holding all or part of a hash value, a node
 * index, and other key pieces of info.
 *
 * - 128 bytes/bucket with 19 bytes/entry gives 6 entries, or 5 entries plus
 * next bucket ptr if overflow Changes in this structure will affect
 * hicn_hash_bucket_t
 */
typedef struct __attribute__ ((packed)) hicn_hash_entry_s
{

  /* MSB of the hash value */
  u64 he_msb64;

  /* Index of node block */
  u32 he_node;

  /*
   * Lock to prevent hash_node deletion while there are still interest
   * or data referring to it
   */
  u32 locks;

  /* Index of dpo (4B) */
  index_t dpo_ctx_id;

  /* A few flags, including 'this points to a chain of buckets' */
  u8 he_flags;

  /*
   * Index of the virtual function table corresponding to the dpo_ctx
   * strategy
   */
  u8 vft_id;

} hicn_hash_entry_t;		//size 22B

STATIC_ASSERT (sizeof (index_t) <= 4, "sizeof index_t is greater than 4B");


#define HICN_HASH_ENTRY_FLAGS_DEFAULT  0x00

/* If entry is PIT this flag is 0 */
#define HICN_HASH_ENTRY_FLAG_CS_ENTRY  0x01

/*
 * This entry heads a chain of overflow buckets (we expect to see this only
 * in the last entry in a bucket.) In this case, the index is to an overflow
 * bucket rather than to a single node block.
 */
#define HICN_HASH_ENTRY_FLAG_OVERFLOW  0x04

/* This entry has been marked for deletion */
#define HICN_HASH_ENTRY_FLAG_DELETED   0x08

/* Use fast he_timeout units for expiration, slow if not */
#define HICN_HASH_ENTRY_FLAG_FAST_TIMEOUT 0x10

/*
 * hash bucket: Contains an array of entries. Cache line sized/aligned, so no
 * room for extra fields unless bucket size is increased to 2 cache lines or
 * the entry struct shrinks.
 */

/*
 * Overflow bucket ratio as a fraction of the fixed/configured count; a pool
 * of hash buckets used if a row in the fixed table overflows.
 */
#define HICN_HASHTB_BUCKET_ENTRIES 5

typedef struct __attribute__ ((packed))
{
  hicn_hash_entry_t hb_entries[HICN_HASHTB_BUCKET_ENTRIES];
  u64 align1;
  u64 align2;
  u16 align3;
} hicn_hash_bucket_t;

/* Overall target fill-factor for the hashtable */
#define HICN_HASHTB_FILL_FACTOR    4

#define HICN_HASHTB_MIN_ENTRIES  (1 << 4)	// includes dummy node 0 entry
#define HICN_HASHTB_MAX_ENTRIES  (1 << 24)

#define HICN_HASHTB_MIN_BUCKETS (1 << 10)

/*
 * htab_t
 *
 * Hash table main structure.
 *
 * Contains - pointers to dynamically allocated arrays of cache-line
 * sized/aligned structures (buckets, nodes, keys). Put frequently accessed
 * fields in the first cache line.
 */
typedef struct hicn_hashtb_s
{

  /* 8B - main array of hash buckets */
  hicn_hash_bucket_t *ht_buckets;

  /* 8B - just-in-case block of overflow buckets */
  hicn_hash_bucket_t *ht_overflow_buckets;

  /* 8B - block of nodes associated with entries in buckets */
  hicn_hash_node_t *ht_nodes;

  /* Flags */
  u32 ht_flags;

  /* Count of buckets allocated in the main array */
  u32 ht_bucket_count;

  /* Count of overflow buckets allocated */
  u32 ht_overflow_bucket_count;
  u32 ht_overflow_buckets_used;

  /* Count of nodes allocated */
  u32 ht_node_count;
  u32 ht_nodes_used;

  /* Count of overflow key structs allocated */
  u32 ht_key_count;
  u32 ht_keys_used;

} hicn_hashtb_t, *hicn_hashtb_h;

/*
 * Offset to aligned start of additional data (PIT/CS, FIB) embedded in each
 * node.
 */
extern u32 ht_node_data_offset_aligned;

/* Flags for hashtable */

#define HICN_HASHTB_FLAGS_DEFAULT    0x00

/*
 * Don't use the last entry in each bucket - only use it for overflow. We use
 * this for the FIB, currently, so that we can support in-place FIB changes
 * that would be difficult if there were hash entry copies as part of
 * overflow handling.
 */
#define HICN_HASHTB_FLAG_USE_SEVEN      0x04
#define HICN_HASHTB_FLAG_KEY_FMT_PFX    0x08
#define HICN_HASHTB_FLAG_KEY_FMT_NAME   0x10

/*
 * Max prefix name components we'll support in our incremental hashing;
 * currently used only for LPM in the FIB.
 */
#define HICN_HASHTB_MAX_NAME_COMPS HICN_PARAM_FIB_ENTRY_PFX_COMPS_MAX

/*
 * APIs and inlines
 */

/* Compute hash node index from node pointer */
static inline u32
hicn_hashtb_node_idx_from_node (hicn_hashtb_h h, hicn_hash_node_t * p)
{
  return (p - h->ht_nodes);
}

/* Retrieve a hashtable node by node index */
static inline hicn_hash_node_t *
hicn_hashtb_node_from_idx (hicn_hashtb_h h, u32 idx)
{
  return (pool_elt_at_index (h->ht_nodes, idx));
}

/* Allocate a brand-new hashtable */
int
hicn_hashtb_alloc (hicn_hashtb_h * ph, u32 max_elems, size_t app_data_size);

/* Free a hashtable, including its embedded arrays */
int hicn_hashtb_free (hicn_hashtb_h * ph);

/* Hash a bytestring, currently using bihash */
u64 hicn_hashtb_hash_bytestring (const u8 * key, u32 keylen);

always_inline hicn_hash_entry_t *
hicn_hashtb_get_entry (hicn_hashtb_h h, u32 entry_idx, u32 bucket_id,
		       u8 bucket_overflow)
{
  hicn_hash_bucket_t *bucket;
  if (bucket_overflow)
    bucket = pool_elt_at_index (h->ht_overflow_buckets, bucket_id);
  else
    bucket = (hicn_hash_bucket_t *) (h->ht_buckets + bucket_id);

  return &(bucket->hb_entries[entry_idx]);
}

/* Hash a name, currently using bihash */
always_inline u64
hicn_hashtb_hash_name (const u8 * key, u16 keylen)
{
  if (key != NULL && keylen == HICN_V4_NAME_LEN)
    {
      clib_bihash_kv_8_8_t kv;
      kv.key = ((u64 *) key)[0];
      return clib_bihash_hash_8_8 (&kv);
    }
  else if (key != NULL && keylen == HICN_V6_NAME_LEN)
    {
      clib_bihash_kv_24_8_t kv;
      kv.key[0] = ((u64 *) key)[0];
      kv.key[1] = ((u64 *) key)[1];
      kv.key[2] = ((u32 *) key)[4];
      return clib_bihash_hash_24_8 (&kv);
    }
  else
    {
      return (-1LL);
    }
}


/*
 * Prepare a hashtable node for insertion, supplying the key and computed
 * hash info. This sets up the node->key relationship, possibly allocating
 * overflow key buffers.
 */
void
hicn_hashtb_init_node (hicn_hashtb_h h, hicn_hash_node_t * node,
		       const u8 * key, u32 keylen);

/*
 * Insert a node into the hashtable. We expect the caller has used the init
 * api to set the node key and hash info, and populated the extra data area
 * (if any) - or done the equivalent work itself.
 */
int
hicn_hashtb_insert (hicn_hashtb_h h, hicn_hash_node_t * node,
		    hicn_hash_entry_t ** hash_entry, u64 hash,
		    u32 * node_id,
		    index_t * dpo_ctx_id, u8 * vft_id, u8 * is_cs,
		    u8 * hash_entry_id, u32 * bucket_id,
		    u8 * bucket_is_overflow);

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
			 u8 * bucket_is_overflow);

/*
 * Extended api to lookup a specific hash+key tuple. The implementation
 * allows the caller to locate nodes that are marked for deletion; this is
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
			    u8 * bucket_is_overflow);

/**
 * @brief Compares the key in the node with the given key
 *
 * This function allows to split the hash verification from the comparison of
 * the entire key. Useful to exploit prefertching.
 * @result 1 if equals, 0 otherwise
 */
int hicn_node_compare (const u8 * key, u32 keylen, hicn_hash_node_t * node);

/*
 * Remove a node from a hashtable using the node itself. The internal data
 * structs are cleaned up, but the node struct itself is not: the caller must
 * free the node itself.
 */
void hicn_hashtb_remove_node (hicn_hashtb_h h, hicn_hash_node_t * node,
			      u64 hashval);

/*
 * Delete a node from a hashtable using the node itself, and delete/free the
 * node.  Caller's pointer is cleared on success.
 */
void hicn_hashtb_delete (hicn_hashtb_h h, hicn_hash_node_t ** pnode,
			 u64 hashval);

/*
 * Utility to init a new entry in a hashtable bucket/row. We use this to add
 * new a node+hash, and to clear out an entry during removal.
 */
void
hicn_hashtb_init_entry (hicn_hash_entry_t * entry,
			u32 nodeidx, u64 hashval, u32 locks);


/*
 * Return data area embedded in a hash node struct. We maintain an 'offset'
 * value in case the common node body struct doesn't leave the data area
 * aligned properly.
 */
static inline void *
hicn_hashtb_node_data (hicn_hash_node_t * node)
{
  return ((u8 *) (node) + ht_node_data_offset_aligned);
}

/*
 * Use some bits of the low half of the hash to locate a row/bucket in the
 * table
 */
static inline u32
hicn_hashtb_bucket_idx (hicn_hashtb_h h, u64 hashval)
{
  return ((u32) (hashval & (h->ht_bucket_count - 1)));
}

/*
 * Return a hash node struct from the free list, or NULL. Note that the
 * returned struct is _not_ cleared/zeroed - init is up to the caller.
 */
static inline hicn_hash_node_t *
hicn_hashtb_alloc_node (hicn_hashtb_h h)
{
  hicn_hash_node_t *p = NULL;

  if (h->ht_nodes_used < h->ht_node_count)
    {
      pool_get_aligned (h->ht_nodes, p, 8);
      h->ht_nodes_used++;
    }
  return (p);
}

/*
 * Release a hashtable node back to the free list when an entry is cleared
 */
void hicn_hashtb_free_node (hicn_hashtb_h h, hicn_hash_node_t * node);

/*
 * Walk a hashtable, iterating through the nodes, keeping context in 'ctx'
 * between calls.
 *
 * Set the context value to HICN_HASH_WALK_CTX_INITIAL to start an iteration.
 */
int
hicn_hashtb_next_node (hicn_hashtb_h h, hicn_hash_node_t ** pnode, u64 * ctx);


int
hicn_hashtb_key_to_str (hicn_hashtb_h h, const hicn_hash_node_t * node,
			char *buf, int bufsize, int must_fit);

/*
 * single hash full name can pass offset for two hashes calculation in case
 * we use CS and PIT in a two steps hashes (prefix + seqno)
 */
always_inline int
hicn_hashtb_fullhash (const u8 * name, u16 namelen, u64 * name_hash)
{
  *name_hash = hicn_hashtb_hash_name (name, namelen);
  return (*name_hash != (-1LL) ? HICN_ERROR_NONE : HICN_ERROR_HASHTB_INVAL);
}

#endif /* // __HICN_HASHTB_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
