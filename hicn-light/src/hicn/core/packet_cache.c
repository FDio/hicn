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

pkt_cache_t *pkt_cache_create(size_t cs_size) {
  pkt_cache_t *pkt_cache = (pkt_cache_t *)malloc(sizeof(pkt_cache_t));

  pkt_cache->pit = pit_create();
  if (!pkt_cache->pit) return NULL;
  pkt_cache->cs = cs_create(cs_size);
  if (!pkt_cache->cs) return NULL;

  pkt_cache->index_by_name = kh_init(pkt_cache_name);
  pool_init(pkt_cache->entries, DEFAULT_PKT_CACHE_SIZE, 0);

  return pkt_cache;
}

void pkt_cache_free(pkt_cache_t *pkt_cache) {
  assert(pkt_cache);

  // Free hashmap
  const Name *k_name;
  unsigned v;
  (void)v;
  kh_foreach(pkt_cache->index_by_name, k_name, v, { free((Name *)k_name); });
  kh_destroy(pkt_cache_name, pkt_cache->index_by_name);

  // Free pool
  pool_free(pkt_cache->entries);

  // Free PIT and CS
  pit_free(pkt_cache->pit);
  cs_free(pkt_cache->cs);

  free(pkt_cache);
}

pit_t *pkt_cache_get_pit(pkt_cache_t *pkt_cache) { return pkt_cache->pit; }

cs_t *pkt_cache_get_cs(pkt_cache_t *pkt_cache) { return pkt_cache->cs; }

pkt_cache_entry_t *pkt_cache_lookup(pkt_cache_t *pkt_cache, const Name *name,
                                    msgbuf_pool_t *msgbuf_pool,
                                    pkt_cache_lookup_t *lookup_result,
                                    off_t *entry_id,
                                    bool is_serve_from_cs_enabled) {
  Name name_key = name_key_factory(name);
  khiter_t k = kh_get_pkt_cache_name(pkt_cache->index_by_name, &name_key);
  if (k == kh_end(pkt_cache->index_by_name)) {
    *lookup_result = PKT_CACHE_LU_NONE;
    return NULL;
  }

  off_t index = kh_val(pkt_cache->index_by_name, k);
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

  Name name_key = name_key_factory(msgbuf_get_name(msgbuf));
  khiter_t k = kh_get_pkt_cache_name(pkt_cache->index_by_name, &name_key);
  assert(k != kh_end(pkt_cache->index_by_name));
  free((Name *)kh_key(pkt_cache->index_by_name, k));
  kh_del(pkt_cache_name, pkt_cache->index_by_name, k);

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

  Name name_key = name_key_factory(name);
  khiter_t k = kh_get_pkt_cache_name(pkt_cache->index_by_name, &name_key);
  assert(k != kh_end(pkt_cache->index_by_name));
  free((Name *)kh_key(pkt_cache->index_by_name, k));
  kh_del(pkt_cache_name, pkt_cache->index_by_name, k);

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

  int tail_id = pkt_cache->cs->lru.tail;
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
                                        const msgbuf_t *msgbuf) {
  assert(pkt_cache);

  pkt_cache_entry_t *entry =
      pkt_cache_allocate(pkt_cache, msgbuf_get_name(msgbuf));
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
                                    const msgbuf_t *msgbuf) {
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
    char *name_str = name_ToString(msgbuf_get_name(msgbuf));
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
      ERROR("Inivalid packet cache content");
      return NULL;
  }
}

void pkt_cache_on_interest(pkt_cache_t *pkt_cache, msgbuf_pool_t *msgbuf_pool,
                           off_t msgbuf_id, pkt_cache_verdict_t *verdict,
                           off_t *data_msgbuf_id, pkt_cache_entry_t **entry_ptr,
                           bool is_serve_from_cs_enabled) {
  assert(pkt_cache);
  assert(msgbuf_id_is_valid(msgbuf_id));

  msgbuf_t *msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
  assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

  off_t entry_id;
  pkt_cache_lookup_t lookup_result;
  pkt_cache_entry_t *entry =
      pkt_cache_lookup(pkt_cache, msgbuf_get_name(msgbuf), msgbuf_pool,
                       &lookup_result, &entry_id, is_serve_from_cs_enabled);
  *entry_ptr = entry;

  cs_entry_t *cs_entry = NULL;
  bool is_cs_miss = true;
  bool is_aggregated;
  switch (lookup_result) {
    case PKT_CACHE_LU_NONE:
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
      is_aggregated = pkt_cache_try_aggregate_in_pit(pkt_cache, entry, msgbuf);

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

  const Name *k_name;
  unsigned v_pool_pos;
  kh_foreach(pkt_cache->index_by_name, k_name, v_pool_pos,
             {
               khiter_t k =
                   kh_get_pkt_cache_name(pkt_cache->index_by_name, k_name);
               assert(k != kh_end(pkt_cache->index_by_name));

               pkt_cache_entry_t *entry = pkt_cache_at(pkt_cache, v_pool_pos);
               if (entry->entry_type == PKT_CACHE_CS_TYPE) {
                 // Remove from hashmap
                 free((Name *)kh_key(pkt_cache->index_by_name, k));
                 kh_del(pkt_cache_name, pkt_cache->index_by_name, k);

                 // Remove from pool
                 pool_put(pkt_cache->entries, entry);
               }
             })

      // Re-create CS
      cs_clear(pkt_cache->cs);
}

size_t pkt_cache_get_size(pkt_cache_t *pkt_cache) {
  uint64_t hashmap_size = kh_size(pkt_cache->index_by_name);
  return hashmap_size;
}

size_t pkt_cache_get_cs_size(pkt_cache_t *pkt_cache) {
  return pkt_cache->cs->num_entries;
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

size_t pkt_cache_get_pit_size(pkt_cache_t *pkt_cache) {
  uint64_t hashmap_size = kh_size(pkt_cache->index_by_name);
  uint64_t pit_size = hashmap_size - pkt_cache->cs->num_entries;
  return pit_size;
}

void pkt_cache_log(pkt_cache_t *pkt_cache) {
  uint64_t hashmap_size = kh_size(pkt_cache->index_by_name);
  uint64_t pit_size = hashmap_size - pkt_cache->cs->num_entries;
  DEBUG("Packet cache: total size = %lu, PIT size = %lu, CS size = %u",
        hashmap_size, pit_size, pkt_cache->cs->num_entries);

  cs_log(pkt_cache->cs);
}
