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

/**
 * \file packet_cache.c
 * \brief Implementation of hICN packet cache
 */

#include "packet_cache.h"

/******************************************************************************
 * Low-level operations on the hash table
 ******************************************************************************/

void _prefix_map_free(kh_pkt_cache_prefix_t *prefix_to_suffixes) {
  const NameBitvector *key;
  kh_pkt_cache_suffix_t *value;
  kh_foreach(prefix_to_suffixes, key, value, {
    free((NameBitvector *)key);
    kh_destroy_pkt_cache_suffix(value);
  });
  kh_destroy_pkt_cache_prefix(prefix_to_suffixes);
}

kh_pkt_cache_suffix_t *_get_suffixes(kh_pkt_cache_prefix_t *prefix_to_suffixes,
                                     const NameBitvector *prefix) {
  khiter_t k = kh_get_pkt_cache_prefix(prefix_to_suffixes, prefix);

  // Return suffixes found
  if (k != kh_end(prefix_to_suffixes)) {
    kh_pkt_cache_suffix_t *suffixes = kh_val(prefix_to_suffixes, k);
    return suffixes;
  }

  kh_pkt_cache_suffix_t *suffixes = kh_init_pkt_cache_suffix();
  NameBitvector *nb_copy = (NameBitvector *)malloc(sizeof(NameBitvector));
  *nb_copy = *prefix;

  int rc;
  k = kh_put_pkt_cache_prefix(prefix_to_suffixes, nb_copy, &rc);
  assert(rc == KH_ADDED || rc == KH_RESET);
  kh_value(prefix_to_suffixes, k) = suffixes;
  return suffixes;
}

void _remove_suffix(kh_pkt_cache_prefix_t *prefixes,
                    const NameBitvector *prefix, uint32_t suffix) {
  kh_pkt_cache_suffix_t *suffixes = _get_suffixes(prefixes, prefix);
  assert(suffixes != NULL);

  khiter_t k = kh_get_pkt_cache_suffix(suffixes, suffix);
  assert(k != kh_end(suffixes));
  kh_del_pkt_cache_suffix(suffixes, k);

  // TODO(eloparco): Remove prefix if no associated suffixes?
}

void __add_suffix(kh_pkt_cache_suffix_t *suffixes, uint32_t suffix,
                  unsigned val) {
  int rc;
  khiter_t k = kh_put_pkt_cache_suffix(suffixes, suffix, &rc);
  assert(rc == KH_ADDED || rc == KH_RESET);
  kh_value(suffixes, k) = val;
}

void _add_suffix(kh_pkt_cache_prefix_t *prefixes, const NameBitvector *prefix,
                 uint32_t suffix, unsigned val) {
  kh_pkt_cache_suffix_t *suffixes = _get_suffixes(prefixes, prefix);
  assert(suffixes != NULL);

  __add_suffix(suffixes, suffix, val);
}

unsigned __get_suffix(kh_pkt_cache_suffix_t *suffixes, uint32_t suffix,
                      int *rc) {
  *rc = KH_FOUND;
  khiter_t k = kh_get_pkt_cache_suffix(suffixes, suffix);

  // Not Found
  if (k == kh_end(suffixes)) {
    *rc = KH_NOT_FOUND;
    return -1;
  }

  unsigned index = kh_val(suffixes, k);
  return index;
}

void pkt_cache_save_suffixes_for_prefix(pkt_cache_t *pkt_cache,
                                        const NameBitvector *prefix) {
  // Cached prefix matches the current one
  if (nameBitvector_Compare(&pkt_cache->cached_prefix, prefix) == 0) return;

  // Update cached prefix information
  pkt_cache->cached_prefix = *prefix;
  pkt_cache->cached_suffixes =
      _get_suffixes(pkt_cache->prefix_to_suffixes, prefix);
}

void pkt_cache_reset_suffixes_for_prefix(pkt_cache_t *pkt_cache) {
  pkt_cache->cached_suffixes = NULL;
}

unsigned _get_suffix(kh_pkt_cache_prefix_t *prefixes,
                     const NameBitvector *prefix, uint32_t suffix, int *rc) {
  kh_pkt_cache_suffix_t *suffixes = _get_suffixes(prefixes, prefix);
  assert(suffixes != NULL);

  return __get_suffix(suffixes, suffix, rc);
}

/******************************************************************************
 * Public API
 ******************************************************************************/

pkt_cache_t *pkt_cache_create(size_t cs_size) {
  pkt_cache_t *pkt_cache = (pkt_cache_t *)malloc(sizeof(pkt_cache_t));

  pkt_cache->pit = pit_create();
  if (!pkt_cache->pit) return NULL;
  pkt_cache->cs = cs_create(cs_size);
  if (!pkt_cache->cs) return NULL;

  pkt_cache->prefix_to_suffixes = kh_init_pkt_cache_prefix();
  pool_init(pkt_cache->entries, DEFAULT_PKT_CACHE_SIZE, 0);

  pkt_cache->cached_prefix = EMPTY_NAME_BITVECTOR;
  pkt_cache->cached_suffixes = NULL;

  return pkt_cache;
}

void pkt_cache_free(pkt_cache_t *pkt_cache) {
  assert(pkt_cache);

  // Free prefix hash table and pool
  _prefix_map_free(pkt_cache->prefix_to_suffixes);
  pool_free(pkt_cache->entries);

  // Free PIT and CS
  pit_free(pkt_cache->pit);
  cs_free(pkt_cache->cs);

  free(pkt_cache);
}

kh_pkt_cache_suffix_t *pkt_cache_get_suffixes(const pkt_cache_t *pkt_cache,
                                              const NameBitvector *prefix) {
  return _get_suffixes(pkt_cache->prefix_to_suffixes, prefix);
}

pkt_cache_entry_t *pkt_cache_allocate(pkt_cache_t *pkt_cache,
                                      const Name *name) {
  pkt_cache_entry_t *entry = NULL;
  pool_get(pkt_cache->entries, entry);
  if (!entry) return NULL;

  off_t id = entry - pkt_cache->entries;

  if (pkt_cache->cached_suffixes) {
    __add_suffix(pkt_cache->cached_suffixes, name_GetSegment(name),
                 (unsigned int)id);
  } else {
    _add_suffix(pkt_cache->prefix_to_suffixes, name_GetContentName(name),
                name_GetSegment(name), (unsigned int)id);
  }

  return entry;
}

pit_t *pkt_cache_get_pit(pkt_cache_t *pkt_cache) { return pkt_cache->pit; }

cs_t *pkt_cache_get_cs(pkt_cache_t *pkt_cache) { return pkt_cache->cs; }

pkt_cache_entry_t *pkt_cache_lookup(pkt_cache_t *pkt_cache, const Name *name,
                                    msgbuf_pool_t *msgbuf_pool,
                                    pkt_cache_lookup_t *lookup_result,
                                    off_t *entry_id,
                                    bool is_serve_from_cs_enabled) {
  int rc;

  unsigned index = -1;
  if (pkt_cache->cached_suffixes) {
    index =
        __get_suffix(pkt_cache->cached_suffixes, name_GetSegment(name), &rc);
  } else {
    index = _get_suffix(pkt_cache->prefix_to_suffixes,
                        name_GetContentName(name), name_GetSegment(name), &rc);
  }

  if (rc == KH_NOT_FOUND) {
    *lookup_result = PKT_CACHE_LU_NONE;
    return NULL;
  }

  pkt_cache_entry_t *entry = pkt_cache_at(pkt_cache, index);
  assert(entry);
  bool expired = false;
  if (entry->has_expire_ts && ticks_now() >= entry->expire_ts) {
    expired = true;
  }

  if (entry->entry_type == PKT_CACHE_CS_TYPE) {
    if (expired)
      *lookup_result = PKT_CACHE_LU_DATA_EXPIRED;
    else
      *lookup_result = PKT_CACHE_LU_DATA_NOT_EXPIRED;
  } else {  // PKT_CACHE_PIT_TYPE
    if (expired)
      *lookup_result = PKT_CACHE_LU_INTEREST_EXPIRED;
    else
      *lookup_result = PKT_CACHE_LU_INTEREST_NOT_EXPIRED;
  }

  *entry_id = index;
  return entry;
}

void pkt_cache_cs_remove_entry(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry,
                               msgbuf_pool_t *msgbuf_pool, bool is_evicted) {
  assert(pkt_cache);
  assert(entry);
  assert(entry->entry_type == PKT_CACHE_CS_TYPE);

  off_t msgbuf_id = entry->u.cs_entry.msgbuf_id;
  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

  const Name *name = msgbuf_get_name(msgbuf);
  _remove_suffix(pkt_cache->prefix_to_suffixes, name_GetContentName(name),
                 name_GetSegment(name));

  // Do not update the LRU cache for evicted entries
  if (!is_evicted) cs_vft[pkt_cache->cs->type]->remove_entry(pkt_cache, entry);

  pkt_cache->cs->num_entries--;
  pool_put(pkt_cache->entries, entry);

  WITH_DEBUG({
    char *name_str = name_ToString(msgbuf_get_name(msgbuf));
    DEBUG("Packet %s removed from CS", name_str);
    free(name_str);
  })

  msgbuf_pool_release(msgbuf_pool, &msgbuf);
}

void pkt_cache_pit_remove_entry(pkt_cache_t *pkt_cache,
                                pkt_cache_entry_t *entry, const Name *name) {
  assert(pkt_cache);
  assert(entry);
  assert(entry->entry_type == PKT_CACHE_PIT_TYPE);

  _remove_suffix(pkt_cache->prefix_to_suffixes, name_GetContentName(name),
                 name_GetSegment(name));
  pool_put(pkt_cache->entries, entry);

  WITH_DEBUG({
    char *name_str = name_ToString(name);
    DEBUG("Packet %s removed from PIT", name_str);
    free(name_str);
  })
}

void _pkt_cache_add_to_cs(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry,
                          msgbuf_pool_t *msgbuf_pool, msgbuf_t *msgbuf,
                          off_t msgbuf_id, off_t entry_id) {
  entry->u.cs_entry =
      (cs_entry_t){.msgbuf_id = msgbuf_id,
                   .lru = {.prev = INVALID_ENTRY_ID, .next = INVALID_ENTRY_ID}};
  entry->create_ts = ticks_now();
  entry->expire_ts = ticks_now() + msgbuf_get_data_expiry_time(msgbuf);
  entry->has_expire_ts = true;
  entry->entry_type = PKT_CACHE_CS_TYPE;

  pkt_cache->cs->num_entries++;

  int tail_id = (int)(pkt_cache->cs->lru.tail);
  int result = cs_vft[pkt_cache->cs->type]->add_entry(pkt_cache, entry_id);
  if (result == LRU_EVICTION) {
    // Remove tail (already removed from LRU cache)
    pkt_cache_entry_t *tail = pkt_cache_entry_at(pkt_cache, tail_id);
    assert(tail->entry_type == PKT_CACHE_CS_TYPE);
    pkt_cache_cs_remove_entry(pkt_cache, tail, msgbuf_pool, true);
  }

  // Acquired by CS
  msgbuf_pool_acquire(msgbuf);
}

void pkt_cache_pit_to_cs(pkt_cache_t *pkt_cache,
                         pkt_cache_entry_t *interest_entry,
                         msgbuf_pool_t *msgbuf_pool, msgbuf_t *data_msgbuf,
                         off_t data_msgbuf_id, off_t entry_id) {
  assert(pkt_cache);
  assert(interest_entry);
  assert(interest_entry->entry_type == PKT_CACHE_PIT_TYPE);

  _pkt_cache_add_to_cs(pkt_cache, interest_entry, msgbuf_pool, data_msgbuf,
                       data_msgbuf_id, entry_id);
}

void _pkt_cache_add_to_pit(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry,
                           const msgbuf_t *msgbuf) {
  entry->u.pit_entry = (pit_entry_t){
      .ingressIdSet = NEXTHOPS_EMPTY,
      .egressIdSet = NEXTHOPS_EMPTY,
      .fib_entry = NULL,
  };
  pit_entry_ingress_add(&entry->u.pit_entry, msgbuf_get_connection_id(msgbuf));

  entry->create_ts = ticks_now();
  entry->expire_ts = ticks_now() + msgbuf_get_interest_lifetime(msgbuf);
  entry->has_expire_ts = true;
  entry->entry_type = PKT_CACHE_PIT_TYPE;
}

void pkt_cache_cs_to_pit(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry,
                         msgbuf_pool_t *msgbuf_pool, const msgbuf_t *msgbuf,
                         off_t msgbuf_id, off_t entry_id) {
  assert(pkt_cache);
  assert(entry);
  assert(entry->entry_type == PKT_CACHE_CS_TYPE);

  // Release data associated with expired CS entry
  off_t cs_entry_msgbuf_id = entry->u.cs_entry.msgbuf_id;
  msgbuf_t *cs_entry_msgbuf = msgbuf_pool_at(msgbuf_pool, cs_entry_msgbuf_id);
  msgbuf_pool_release(msgbuf_pool, &cs_entry_msgbuf);

  cs_vft[pkt_cache->cs->type]->remove_entry(pkt_cache, entry);
  _pkt_cache_add_to_pit(pkt_cache, entry, msgbuf);
  pkt_cache->cs->num_entries--;
}

void pkt_cache_update_cs(pkt_cache_t *pkt_cache, msgbuf_pool_t *msgbuf_pool,
                         pkt_cache_entry_t *entry, msgbuf_t *msgbuf,
                         off_t msgbuf_id) {
  assert(pkt_cache);
  assert(entry);
  assert(entry->entry_type == PKT_CACHE_CS_TYPE);

  // Release previous msgbuf and acquire new one
  msgbuf_t *prev_msgbuf =
      msgbuf_pool_at(msgbuf_pool, entry->u.cs_entry.msgbuf_id);
  msgbuf_pool_release(msgbuf_pool, &prev_msgbuf);
  msgbuf_pool_acquire(msgbuf);

  entry->u.cs_entry.msgbuf_id = msgbuf_id;
  entry->create_ts = ticks_now();
  entry->expire_ts = ticks_now() + msgbuf_get_data_expiry_time(msgbuf);
  entry->has_expire_ts = true;

  cs_vft[pkt_cache->cs->type]->update_entry(pkt_cache, entry);
}

pkt_cache_entry_t *pkt_cache_add_to_pit(pkt_cache_t *pkt_cache,
                                        const msgbuf_t *msgbuf,
                                        const Name *name) {
  assert(pkt_cache);

  pkt_cache_entry_t *entry = pkt_cache_allocate(pkt_cache, name);
  _pkt_cache_add_to_pit(pkt_cache, entry, msgbuf);
  return entry;
}

pkt_cache_entry_t *pkt_cache_add_to_cs(pkt_cache_t *pkt_cache,
                                       msgbuf_pool_t *msgbuf_pool,
                                       msgbuf_t *msgbuf, off_t msgbuf_id) {
  assert(pkt_cache);

  pkt_cache_entry_t *entry =
      pkt_cache_allocate(pkt_cache, msgbuf_get_name(msgbuf));
  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);
  _pkt_cache_add_to_cs(pkt_cache, entry, msgbuf_pool, msgbuf, msgbuf_id,
                       entry_id);

  return entry;
}

void pkt_cache_update_pit(pkt_cache_t *pkt_cache, pkt_cache_entry_t *entry,
                          const msgbuf_t *msgbuf) {
  assert(pkt_cache);
  assert(entry);
  assert(entry->entry_type == PKT_CACHE_PIT_TYPE);

  pit_entry_t *pit_entry = &entry->u.pit_entry;
  fib_entry_t *fib_entry = pit_entry_get_fib_entry(pit_entry);
  if (fib_entry)
    fib_entry_on_timeout(fib_entry, pit_entry_get_egress(pit_entry));

  _pkt_cache_add_to_pit(pkt_cache, entry, msgbuf);
}

bool pkt_cache_try_aggregate_in_pit(pkt_cache_t *pkt_cache,
                                    pkt_cache_entry_t *entry,
                                    const msgbuf_t *msgbuf, const Name *name) {
  assert(pkt_cache);
  assert(entry);
  assert(entry->entry_type == PKT_CACHE_PIT_TYPE);

  pit_entry_t *pit_entry = &entry->u.pit_entry;

  // Extend entry lifetime
  Ticks expire_ts = ticks_now() + msgbuf_get_interest_lifetime(msgbuf);
  if (expire_ts > entry->expire_ts) entry->expire_ts = expire_ts;

  // Check if the reverse path is already present
  // in the PIT entry (i.e. it is a retransmission)
  unsigned connection_id = msgbuf_get_connection_id(msgbuf);
  bool is_aggregated = !pit_entry_ingress_contains(pit_entry, connection_id);
  if (is_aggregated) pit_entry_ingress_add(pit_entry, connection_id);

  WITH_DEBUG({
    char *name_str = name_ToString(name);
    if (is_aggregated) {
      DEBUG("Interest %s already existing (expiry %lu): aggregate", name_str,
            entry->expire_ts);
    } else {
      DEBUG("Interest %s already existing (expiry %lu): retransmit", name_str,
            entry->expire_ts);
    }
    free(name_str);
  })

  return is_aggregated;
}

nexthops_t *pkt_cache_on_data(pkt_cache_t *pkt_cache,
                              msgbuf_pool_t *msgbuf_pool, off_t msgbuf_id,
                              bool is_cs_store_enabled,
                              bool is_connection_local, bool *wrong_egress,
                              pkt_cache_verdict_t *verdict) {
  assert(pkt_cache);
  assert(msgbuf_id_is_valid(msgbuf_id));

  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
  assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA);

  *wrong_egress = false;
  off_t entry_id;
  pkt_cache_lookup_t lookup_result;
  pkt_cache_entry_t *entry =
      pkt_cache_lookup(pkt_cache, msgbuf_get_name(msgbuf), msgbuf_pool,
                       &lookup_result, &entry_id, true);

  pit_entry_t *pit_entry;
  fib_entry_t *fib_entry;
  nexthops_t *nexthops = NULL;
  nexthops_t *nexthops_copy;
  switch (lookup_result) {
    case PKT_CACHE_LU_INTEREST_NOT_EXPIRED:
      pit_entry = &entry->u.pit_entry;
      fib_entry = pit_entry_get_fib_entry(pit_entry);
      if (fib_entry)
        fib_entry_on_data(fib_entry, pit_entry_get_egress(pit_entry), msgbuf,
                          entry->create_ts, ticks_now());

      // Check if the data is coming from the exepected connection
      nexthops_t *egressIdSet = pit_entry_get_egress(pit_entry);
      unsigned egress_connection = msgbuf_get_connection_id(msgbuf);
      if (!nexthops_contains(egressIdSet, egress_connection)) {
        *wrong_egress = true;
        return NULL;
      }

      // XXX TODO : be sure nexthops are valid b/c pit entry is removed
      // XXX TODO eventually pass holding structure as parameter
      nexthops = pit_entry_get_ingress(pit_entry);
      assert(nexthops);

      nexthops_copy = (nexthops_t *)malloc(sizeof(*nexthops_copy));
      *nexthops_copy = *nexthops;

      if (is_cs_store_enabled) {
        pkt_cache_pit_to_cs(pkt_cache, entry, msgbuf_pool, msgbuf, msgbuf_id,
                            entry_id);
        *verdict = PKT_CACHE_VERDICT_FORWARD_DATA;
      } else {
        pkt_cache_pit_remove_entry(pkt_cache, entry, msgbuf_get_name(msgbuf));
        *verdict = PKT_CACHE_VERDICT_CLEAR_DATA;
      }

      return nexthops_copy;

    // Data packets are stored in the content store even in the case
    // where there is no match in the PIT, to allow applications to push
    // content to the forwarder's CS. This behavior is allowed only for
    // local faces.
    case PKT_CACHE_LU_INTEREST_EXPIRED:
      if (is_cs_store_enabled && is_connection_local) {
        pkt_cache_pit_to_cs(pkt_cache, entry, msgbuf_pool, msgbuf, msgbuf_id,
                            entry_id);
        *verdict = PKT_CACHE_VERDICT_STORE_DATA;
      } else {
        pkt_cache_pit_remove_entry(pkt_cache, entry, msgbuf_get_name(msgbuf));
        *verdict = PKT_CACHE_VERDICT_CLEAR_DATA;
      }
      return NULL;

    case PKT_CACHE_LU_NONE:
      *verdict = PKT_CACHE_VERDICT_IGNORE_DATA;
      if (is_cs_store_enabled && is_connection_local) {
        pkt_cache_add_to_cs(pkt_cache, msgbuf_pool, msgbuf, msgbuf_id);
        *verdict = PKT_CACHE_VERDICT_STORE_DATA;
      }
      return NULL;

    case PKT_CACHE_LU_DATA_EXPIRED:
      if (is_cs_store_enabled && is_connection_local) {
        pkt_cache_update_cs(pkt_cache, msgbuf_pool, entry, msgbuf, msgbuf_id);
        *verdict = PKT_CACHE_VERDICT_UPDATE_DATA;
      } else {
        pkt_cache_cs_remove_entry(pkt_cache, entry, msgbuf_pool, false);
        *verdict = PKT_CACHE_VERDICT_CLEAR_DATA;
      }
      return NULL;

    case PKT_CACHE_LU_DATA_NOT_EXPIRED:
      *verdict = PKT_CACHE_VERDICT_IGNORE_DATA;
      if (is_cs_store_enabled && is_connection_local) {
        pkt_cache_update_cs(pkt_cache, msgbuf_pool, entry, msgbuf, msgbuf_id);
        *verdict = PKT_CACHE_VERDICT_UPDATE_DATA;
      }
      return NULL;

    default:
      ERROR("Invalid packet cache content");
      return NULL;
  }
}

void pkt_cache_on_interest(pkt_cache_t *pkt_cache, msgbuf_pool_t *msgbuf_pool,
                           off_t msgbuf_id, pkt_cache_verdict_t *verdict,
                           off_t *data_msgbuf_id, pkt_cache_entry_t **entry_ptr,
                           const Name *name, bool is_serve_from_cs_enabled) {
  assert(pkt_cache);
  assert(msgbuf_id_is_valid(msgbuf_id));

  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
  assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

  off_t entry_id;
  pkt_cache_lookup_t lookup_result;
  pkt_cache_entry_t *entry =
      pkt_cache_lookup(pkt_cache, name, msgbuf_pool, &lookup_result, &entry_id,
                       is_serve_from_cs_enabled);
  *entry_ptr = entry;

  cs_entry_t *cs_entry = NULL;
  bool is_cs_miss = true;
  bool is_aggregated;
  switch (lookup_result) {
    case PKT_CACHE_LU_NONE:
      entry = pkt_cache_add_to_pit(pkt_cache, msgbuf, name);
      *entry_ptr = entry;

      *verdict = PKT_CACHE_VERDICT_FORWARD_INTEREST;
      break;

    case PKT_CACHE_LU_DATA_NOT_EXPIRED:
      if (!is_serve_from_cs_enabled) goto PKT_CACHE_LU_DATA_EXPIRED;

      cs_entry = &entry->u.cs_entry;
      *data_msgbuf_id = cs_entry->msgbuf_id;

      *verdict = PKT_CACHE_VERDICT_FORWARD_DATA;
      is_cs_miss = false;
      break;

    case PKT_CACHE_LU_INTEREST_NOT_EXPIRED:
      is_aggregated =
          pkt_cache_try_aggregate_in_pit(pkt_cache, entry, msgbuf, name);

      *verdict = is_aggregated ? PKT_CACHE_VERDICT_AGGREGATE_INTEREST
                               : PKT_CACHE_VERDICT_RETRANSMIT_INTEREST;
      break;

    case PKT_CACHE_LU_INTEREST_EXPIRED:
      pkt_cache_update_pit(pkt_cache, entry, msgbuf);

      *verdict = PKT_CACHE_VERDICT_INTEREST_EXPIRED_FORWARD_INTEREST;
      break;

    case PKT_CACHE_LU_DATA_EXPIRED:
    PKT_CACHE_LU_DATA_EXPIRED:
      pkt_cache_cs_to_pit(pkt_cache, entry, msgbuf_pool, msgbuf, msgbuf_id,
                          entry_id);

      *verdict = PKT_CACHE_VERDICT_DATA_EXPIRED_FORWARD_INTEREST;
      break;

    default:
      *verdict = PKT_CACHE_VERDICT_ERROR;
  }
  is_cs_miss ? cs_miss(pkt_cache->cs) : cs_hit(pkt_cache->cs);
}

void pkt_cache_cs_clear(pkt_cache_t *pkt_cache) {
  assert(pkt_cache);

  kh_pkt_cache_suffix_t *v_suffixes;
  u32 k_suffix;
  u32 v_pkt_cache_entry_id;
  kh_foreach_value(pkt_cache->prefix_to_suffixes, v_suffixes, {
    kh_foreach(v_suffixes, k_suffix, v_pkt_cache_entry_id, {
      pkt_cache_entry_t *entry = pkt_cache_at(pkt_cache, v_pkt_cache_entry_id);
      if (entry->entry_type == PKT_CACHE_CS_TYPE) {
        // Remove from hash table
        khiter_t k = kh_get_pkt_cache_suffix(v_suffixes, k_suffix);
        assert(k != kh_end(v_suffixes));
        kh_del_pkt_cache_suffix(v_suffixes, k);

        // Remove from pool
        pool_put(pkt_cache->entries, entry);
      }
    });
  });

  // Reset cached prefix
  pkt_cache->cached_prefix = EMPTY_NAME_BITVECTOR;
  pkt_cache->cached_suffixes = NULL;

  // Re-create CS
  cs_clear(pkt_cache->cs);
}

size_t pkt_cache_get_num_cs_stale_entries(pkt_cache_t *pkt_cache) {
  size_t num_stale_entries = 0;
  Ticks now = ticks_now();
  pkt_cache_entry_t *entry;

  pool_foreach(pkt_cache->entries, entry, {
    if (entry->entry_type == PKT_CACHE_CS_TYPE && entry->has_expire_ts &&
        now >= entry->expire_ts) {
      num_stale_entries++;
    }
  });

  return num_stale_entries;
}

int pkt_cache_set_cs_size(pkt_cache_t *pkt_cache, size_t size) {
  if (pkt_cache->cs->num_entries > size) return -1;

  pkt_cache->cs->max_size = size;
  return 0;
}

size_t pkt_cache_get_size(pkt_cache_t *pkt_cache) {
  return pool_len(pkt_cache->entries);
}

size_t pkt_cache_get_cs_size(pkt_cache_t *pkt_cache) {
  return pkt_cache->cs->num_entries;
}

size_t pkt_cache_get_pit_size(pkt_cache_t *pkt_cache) {
  uint64_t pkt_cache_size = pkt_cache_get_size(pkt_cache);
  uint64_t pit_size = pkt_cache_size - pkt_cache_get_cs_size(pkt_cache);
  return pit_size;
}

void pkt_cache_log(pkt_cache_t *pkt_cache) {
  DEBUG("Packet cache: total size = %lu, PIT size = %lu, CS size = %u",
        pkt_cache_get_size(pkt_cache), pkt_cache_get_pit_size(pkt_cache),
        pkt_cache_get_cs_size(pkt_cache));

  cs_log(pkt_cache->cs);
}
