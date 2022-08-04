/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

/**
 * \file packet_cache.h
 * \brief hICN packet cache
 *
 * The packet cache is a data structure that merges together the PIT and the CS,
 * to which it holds a reference.
 * It contains PIT and CS entries, indexed in a two-level hash table.
 *
 * Each entry has shared fields, e.g. entry type (PIT or CS) and timestamps,
 * which are used by both PIT and CS entries. In addition, a C union holds
 * the PIT or CS specific fields.
 *
 * Having a single entry that can hold PIT or CS entries allows to reduce
 * the number of lookups.
 *
 * A prefix hash table <prefix, suffix_hashtable> stores the suffixes associated
 * to each prefix, where each value in the map points to a separate hash
 * table <suffix, packet_cache_reference> that can be used to retrieved the
 * packet cache entry.
 * When an interest/data packet is received, the prefix and the associated
 * suffixes are saved; if the next packet cache operation involves the same
 * prefix, no additional lookups in the prefix hash hashtable are needed.
 */

#ifndef HICNLIGHT_PACKET_CACHE_H
#define HICNLIGHT_PACKET_CACHE_H

#include <hicn/util/khash.h>
#include "content_store.h"
#include "pit.h"
#include "msgbuf_pool.h"
#include "../content_store/lru.h"

#define DEFAULT_PKT_CACHE_SIZE 2048

typedef enum { PKT_CACHE_PIT_TYPE, PKT_CACHE_CS_TYPE } pkt_cache_entry_type_t;

#define foreach_kh_verdict             \
  _(FORWARD_INTEREST)                  \
  _(AGGREGATE_INTEREST)                \
  _(RETRANSMIT_INTEREST)               \
  _(FORWARD_DATA)                      \
  _(INTEREST_EXPIRED_FORWARD_INTEREST) \
  _(DATA_EXPIRED_FORWARD_INTEREST)     \
  _(STORE_DATA)                        \
  _(CLEAR_DATA)                        \
  _(UPDATE_DATA)                       \
  _(IGNORE_DATA)                       \
  _(ERROR)

typedef enum {
#define _(x) PKT_CACHE_VERDICT_##x,
  foreach_kh_verdict
#undef _
} pkt_cache_verdict_t;

extern const char *_pkt_cache_verdict_str[];

#define pkt_cache_verdict_str(x) _pkt_cache_verdict_str[x]

#define foreach_kh_lookup \
  _(INTEREST_NOT_EXPIRED) \
  _(INTEREST_EXPIRED)     \
  _(DATA_NOT_EXPIRED)     \
  _(DATA_EXPIRED)         \
  _(NONE)

typedef enum {
#define _(x) PKT_CACHE_LU_##x,
  foreach_kh_lookup
#undef _
} pkt_cache_lookup_t;

KHASH_MAP_INIT_INT(pkt_cache_suffix, unsigned);
KHASH_INIT(pkt_cache_prefix, const hicn_name_prefix_t *,
           kh_pkt_cache_suffix_t *, 1, hicn_name_prefix_get_hash,
           hicn_name_prefix_equals);

typedef struct {
  hicn_name_t name;
  pkt_cache_entry_type_t entry_type;

  Ticks create_ts;
  Ticks expire_ts;
  // TODO(eloparco): Is it necessary?
  // Now it is always set to true
  bool has_expire_ts;

  union {
    pit_entry_t pit_entry;
    cs_entry_t cs_entry;
  } u;
} pkt_cache_entry_t;

typedef struct {
  pit_t *pit;
  cs_t *cs;
  pkt_cache_entry_t *entries;
  kh_pkt_cache_prefix_t *prefix_to_suffixes;

  // Cached prefix info to avoid double lookups,
  // used for both single interest speculation and interest manifest
  hicn_name_prefix_t cached_prefix;
  kh_pkt_cache_suffix_t *cached_suffixes;
} pkt_cache_t;

/**
 * @brief Create a new packet cache.
 *
 * @return pkt_cache_t* The newly created packet cache
 */
pkt_cache_t *pkt_cache_create(size_t cs_size);

/**
 * @brief Add an entry with the specified name to the packet cache.
 *
 * @param[in] pkt_cache Pointer to the pool data structure to use.
 * @param[in, out] entry Empty entry that will be used to return the
 * allocated one from the msgbuf pool.
 * @param[in] name hicn_name_t to use
 *
 * NOTE: unlike other pools, PIT and CS entries allocation does not update the
 * index as the key is a hicn_name_t * which should point to :
 *  - the name inside the PIT entry (which is thus not set during allocation),
 *  - the name inside the msgbuf_t in the CS entry, which is always available
 *  during the lifetime of the cache entry.
 *
 * The index is therefore updated in pkt_cache_add_to_pit and
 * pkt_cache_add_to_cs functions.
 *
 *
 */
pkt_cache_entry_t *pkt_cache_allocate(pkt_cache_t *pkt_cache);

void pkt_cache_add_to_index(const pkt_cache_t *pkt_cache,
                            const pkt_cache_entry_t *entry);

void pkt_cache_remove_from_index(const pkt_cache_t *pkt_cache,
                                 const hicn_name_t *name);

/**
 * @brief Free a packet cache data structure.
 *
 * @param[in] pkt_cache Pointer to packet cache data structure to free.
 */
void pkt_cache_free(pkt_cache_t *pkt_cache);

/**
 * @brief Get a reference to the PIT data structure contained in the packet
 * cache.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to get the
 * PIT from.
 */
pit_t *pkt_cache_get_pit(pkt_cache_t *pkt_cache);

/**
 * @brief Get a reference to the CS data structure contained in the packet
 * cache.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to get the
 * CS from.
 */
cs_t *pkt_cache_get_cs(pkt_cache_t *pkt_cache);

/**
 * @brief Return the total packet cache size (i.e. PIT + CS).
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 */
size_t pkt_cache_get_size(pkt_cache_t *pkt_cache);

/**
 * @brief Return the number of stale entries (i.e. expired) in the CS.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 */
size_t pkt_cache_get_num_cs_stale_entries(pkt_cache_t *pkt_cache);

/**
 * @brief Change the maximum capacity of the content store (LRU eviction will
 * be used after reaching the provided size)
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in] size Maximum size of the content store
 * @return int 0 if success, -1 if the provided maximum size is smaller than
 * the number of elements currently stored in the CS
 */
int pkt_cache_set_cs_size(pkt_cache_t *pkt_cache, size_t size);

/**
 * @brief Return the content store size.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 */
size_t pkt_cache_get_cs_size(pkt_cache_t *pkt_cache);

/**
 * @brief Return the PIT size.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 */
size_t pkt_cache_get_pit_size(pkt_cache_t *pkt_cache);

#define pkt_cache_entry_get_create_ts(E) ((E)->create_ts)
#define pkt_cache_entry_get_expire_ts(E) ((E)->expire_ts)
#define pkt_cache_entry_set_expire_ts(E, EXPIRY_TIME) \
  (entry)->expire_ts = EXPIRY_TIME
#define pkt_cache_get_entry_id(pkt_cache, entry) (entry - pkt_cache->entries)
#define pkt_cache_entry_at(pkt_cache, id) (&(pkt_cache)->entries[id])
#define pkt_cache_at(pkt_cache, i) (pkt_cache->entries + i)

/**
 * @brief Retrieve from the packet cache the entry associated with the
 * specified name.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to retrieve
 * the entry from
 * @param[in] name Packet name to use for the lookup
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use
 * @param[in, out] lookup_result Pointer to store the result of the lookup
 * @param[in, out] entry_id Pointer to store the entry_id in case of a lookup
 * match
 * @param[in] is_serve_from_cs_enabled Boolean to specify if the forwarder is
 * allowed to serve contents from the CS
 * @return pkt_cache_entry_t* Entry retrieved, NULL if none found
 */
pkt_cache_entry_t *pkt_cache_lookup(pkt_cache_t *pkt_cache,
                                    const hicn_name_t *name,
                                    msgbuf_pool_t *msgbuf_pool,
                                    pkt_cache_lookup_t *lookup_result,
                                    off_t *entry_id,
                                    bool is_serve_from_cs_enabled);

/**
 * @brief Clear the content of the CS (PIT entries are left unmodified).
 *
 * @param pkt_cache Pointer to the packet cache data structure to use
 */
void pkt_cache_cs_clear(pkt_cache_t *pkt_cache);

/**
 * @brief Log packet cache statistics.
 *
 * @param pkt_cache Pointer to the packet cache data structure to use
 */
void pkt_cache_log(pkt_cache_t *pkt_cache);

pkt_cache_stats_t pkt_cache_get_stats(pkt_cache_t *pkt_cache);

// TODO(eloparco): To implement
void pkt_cache_print(const pkt_cache_t *pkt_cache);

/************** Packet cache entry operations *************/

/**
 * @brief Remove a content store entry from the packet cache.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in] entry Pointer to the content store entry to remove
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use
 * @param[in] is_evicted Boolean to specify if the content store entry has
 * already been evicted from the LRU cache
 */
void pkt_cache_cs_remove_entry(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry,
                               msgbuf_pool_t *msgbuf_pool, bool is_evicted);

/**
 * @brief Remove a PIT entry from the packet cache.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in] entry Pointer to the PIT entry to remove
 */
void pkt_cache_pit_remove_entry(pkt_cache_t *pkt_cache,
                                pkt_cache_entry_t *entry);

/**
 * @brief Convert a PIT entry to a CS entry.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in, out] entry Pointer to the PIT entry to replace
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use
 * @param[in] msgbuf Pointer to the msgbuf associated with the CS entry to
 * insert
 * @param[in] msgbuf_id Msgbuf ID (i.e. ID in the msgbuf pool) associated with
 * the CS entry to insert
 * @param[in] entry_id Entry ID (i.e. ID in the packet cache pool of entries)
 * associated with the PIT entry to replace
 */
void pkt_cache_pit_to_cs(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry,
                         msgbuf_pool_t *msgbuf_pool, msgbuf_t *msgbuf,
                         off_t msgbuf_id, off_t entry_id);

/**
 * @brief Convert a CS entry to a PIT entry.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in, out] entry Pointer to the CS entry to replace
 * @param[in] msgbuf Pointer to the msgbuf associated with the PIT entry to
 * insert
 * @param[in] msgbuf_id Msgbuf ID (i.e. ID in the msgbuf pool) associated with
 * the PIT entry to insert
 * @param[in] entry_id Entry ID (i.e. ID in the packet cache pool of entries)
 * associated with the CS entry to replace
 */
void pkt_cache_cs_to_pit(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry,
                         msgbuf_pool_t *msgbuf_pool, const msgbuf_t *msgbuf,
                         off_t msgbuf_id, off_t entry_id);

/**
 * @brief Add PIT entry to the packet cache.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in] msgbuf Pointer to the msgbuf associated with the PIT entry to
 * insert
 * @param[in] name Interest name to use; in case of aggregated interests, it is
 * different from the name stored in the msgbuf
 * @return pkt_cache_entry_t* Pointer to the packet cache (PIT) entry created
 */
pkt_cache_entry_t *pkt_cache_add_to_pit(pkt_cache_t *pkt_cache,
                                        const msgbuf_t *msgbuf,
                                        const hicn_name_t *name);

/**
 * @brief Add CS entry to the packet cache.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use
 * @param[in] msgbuf Pointer to the msgbuf associated with the CS entry to
 * insert
 * @param[in] msgbuf_id Msgbuf ID (i.e. ID in the msgbuf pool) associated with
 * the CS entry to insert
 * @return pkt_cache_entry_t* Pointer to the packet cache (CS) entry created
 */
pkt_cache_entry_t *pkt_cache_add_to_cs(pkt_cache_t *pkt_cache,
                                       msgbuf_pool_t *msgbuf_pool,
                                       msgbuf_t *msgbuf, off_t msgbuf_id);

/**
 * @brief Update PIT entry in the packet cache in case of an expired PIT
 * entry.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in, out] entry Pointer to the PIT entry to update
 * @param[in] msgbuf Pointer to the msgbuf associated with the PIT entry to
 * update
 */
void pkt_cache_update_pit(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry,
                          const msgbuf_t *msgbuf);

/**
 * @brief Update CS entry in the packet cache.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in] msgbuf_pool Pointer to the msgbuf pool data structure to use
 * @param[in, out] entry Pointer to the CS entry to update
 * @param[in] msgbuf Pointer to the msgbuf associated with the CS entry to
 * update
 * @param msgbuf_id Msgbuf ID (i.e. ID in the msgbuf pool) associated with the
 * CS entry to update
 */
void pkt_cache_update_cs(pkt_cache_t *pkt_cache, msgbuf_pool_t *msgbuf_pool,
                         pkt_cache_entry_t *entry, msgbuf_t *msgbuf,
                         off_t msgbuf_id);

/**
 * @brief Update PIT entry in the packet cache in case of retransmission or
 * aggregation.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in, out] entry Pointer to the PIT entry to update
 * @param[in] msgbuf Pointer to the msgbuf associated with the PIT entry to
 * update
 * @param[in] name Interest name to use; in case of aggregated interests, it is
 * different from the name stored in the msgbuf
 * @return true If aggregation (interest sent from a connection not stored in
 * the PIT entry)
 * @return false If retransmission (interest sent from a connection already
 * stored in the PIT entry)
 */
bool pkt_cache_try_aggregate_in_pit(pkt_cache_t *pkt_cache,
                                    pkt_cache_entry_t *entry,
                                    const msgbuf_t *msgbuf,
                                    const hicn_name_t *name);

/**
 * @brief Cache prefix info (prefix + associated suffixes) to speed up lookups.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 * @param[in] prefix Name prefix to cache
 */
void pkt_cache_save_suffixes_for_prefix(pkt_cache_t *pkt_cache,
                                        const hicn_name_prefix_t *prefix);

/**
 * @brief Reset cached prefix info to force double lookups.
 *
 * @param[in] pkt_cache Pointer to the packet cache data structure to use
 */
void pkt_cache_reset_suffixes_for_prefix(pkt_cache_t *pkt_cache);

/************ Handle data/interest packets received *******/

/**
 * @brief Handle data packet reception.
 * @details Perform packet cache lookup and execute operations based on it.
 * If:
 *      - INTEREST not expired: Convert PIT entry to CS entry; return the
 *                              nexthops (that can be used to forward the data
 *                              packet now stored in the CS)
 *      - INTEREST expired: Convert PIT entry to CS entry
 *      - DATA expired/not expired: Update the CS
 *      - No match: Add data packet to CS
 */
nexthops_t *pkt_cache_on_data(pkt_cache_t *pkt_cache,
                              msgbuf_pool_t *msgbuf_pool, off_t msgbuf_id,
                              bool is_cs_store_enabled,
                              bool is_connection_local, bool *wrong_egress,
                              pkt_cache_verdict_t *verdict);

/**
 * @brief Handle interest packet reception.
 * @details Perform packet cache lookup and execute operations based on it.
 * If:
 *      - No match: Do nothing
 *      - DATA not expired: get data message from CS
 *      - INTEREST not expired: Aggregate or retransmit the interest received;
 *      - INTEREST expired: Update the PIT;
 *      - DATA expired: Convert CS entry to PIT entry;
 */
void pkt_cache_on_interest(pkt_cache_t *pkt_cache, msgbuf_pool_t *msgbuf_pool,
                           off_t msgbuf_id, pkt_cache_verdict_t *verdict,
                           off_t *data_msgbuf_id, pkt_cache_entry_t **entry_ptr,
                           const hicn_name_t *name,
                           bool is_serve_from_cs_enabled);

/********* Low-level operations on the hash table *********/
#ifdef WITH_TESTS
unsigned __get_suffix(kh_pkt_cache_suffix_t *suffixes,
                      hicn_name_suffix_t suffix);
unsigned _get_suffix(kh_pkt_cache_prefix_t *prefixes,
                     const hicn_name_prefix_t *prefix,
                     hicn_name_suffix_t suffix);
void __add_suffix(kh_pkt_cache_suffix_t *suffixes, hicn_name_suffix_t suffix,
                  unsigned val);
void _add_suffix(kh_pkt_cache_prefix_t *prefixes,
                 const hicn_name_prefix_t *prefix, hicn_name_suffix_t suffix,
                 unsigned val);
void _remove_suffix(kh_pkt_cache_prefix_t *prefixes,
                    const hicn_name_prefix_t *prefix,
                    hicn_name_suffix_t suffix);
void _prefix_map_free(kh_pkt_cache_prefix_t *prefix_to_suffixes);
kh_pkt_cache_suffix_t *_get_suffixes(kh_pkt_cache_prefix_t *prefix_to_suffixes,
                                     const hicn_name_prefix_t *prefix,
                                     bool create);
#endif

/************** Content Store *****************************/

typedef struct {
  const char *name;
  void (*initialize)(cs_t *cs);
  void (*finalize)(cs_t *cs);
  int (*add_entry)(pkt_cache_t *pkt_cache, off_t entry_id);
  void (*update_entry)(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry);
  int (*remove_entry)(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry);
} cs_ops_t;
extern const cs_ops_t *const cs_vft[];

/**
 * @brief Initialize the virtual function table used for the
 * CS cache strategy (e.g. LRU).
 *
 */
#define DECLARE_CS(NAME)                        \
  const cs_ops_t cs_##NAME = {                  \
      .name = #NAME,                            \
      .initialize = cs_##NAME##_initialize,     \
      .finalize = cs_##NAME##_finalize,         \
      .add_entry = cs_##NAME##_add_entry,       \
      .update_entry = cs_##NAME##_update_entry, \
      .remove_entry = cs_##NAME##_remove_entry, \
  }

#endif /* HICNLIGHT_PACKET_CACHE_H */
