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

#ifndef _WIN32
#include <sys/queue.h>
#endif

#include <hicn/util/log.h>

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/core/packet_cache.h>
#include "lru.h"

void cs_lru_initialize(cs_t *cs) {
  /* We start with an empty double-linked list */
  cs->lru.head = INVALID_ENTRY_ID;
  cs->lru.tail = INVALID_ENTRY_ID;
}

void cs_lru_finalize(cs_t *cs) {
  // Nothing to do
}

cs_entry_t *_cs_entry_at(pkt_cache_t *pkt_cache, off_t entry_id) {
  pkt_cache_entry_t *entry = pkt_cache_entry_at(pkt_cache, entry_id);
  assert(entry->entry_type == PKT_CACHE_CS_TYPE);
  return &entry->u.cs_entry;
}

/**
 * Remove a cs_entry_t from all tables and indices.
 */
static int cs_lru_remove_entry(pkt_cache_t *pkt_cache,
                               pkt_cache_entry_t *entry) {
  assert(pkt_cache);
  assert(entry);

  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);
  cs_t *cs = pkt_cache_get_cs(pkt_cache);
  cs_entry_t *cs_entry = &entry->u.cs_entry;

  // If node to be deleted is head node
  if (cs->lru.head == entry_id) cs->lru.head = cs_entry->lru.next;

  // If node to be deleted is tail node
  if (cs->lru.tail == entry_id) cs->lru.tail = cs_entry->lru.prev;

  // If node to be deleted is not the last node
  if (cs_entry->lru.next != INVALID_ENTRY_ID) {
    cs_entry_t *next_cs_entry = _cs_entry_at(pkt_cache, cs_entry->lru.next);
    assert(next_cs_entry);
    next_cs_entry->lru.prev = cs_entry->lru.prev;
  }

  // If node to be deleted is not the first node
  if (cs_entry->lru.prev != INVALID_ENTRY_ID) {
    cs_entry_t *prev_entry = _cs_entry_at(pkt_cache, cs_entry->lru.prev);
    assert(prev_entry);
    prev_entry->lru.next = cs_entry->lru.next;
  }

  cs->stats.lru.countLruDeletions++;
  return LRU_SUCCESS;
}

/**
 * @brief LRU processing related to the insertion of a new entry in the content
 * store (helper).
 * @param[in] cs Content store.
 * @param[in] entry_id Identifier of the entry in the content store entry pool.
 * @param[in] is_update Boolean value to distinguish update from add operations
 * since an update involves removing an entry and adding it again
 *
 * @return int Error code : 0 if succesful, a negative value otherwise.
 *
 * NOTE:
 *  - We insert the new element at the head of the double-linked list.
 */
int _cs_lru_add_entry(pkt_cache_t *pkt_cache, off_t entry_id, bool is_update) {
  assert(pkt_cache);

  cs_t *cs = pkt_cache_get_cs(pkt_cache);
  cs_entry_t *entry = _cs_entry_at(pkt_cache, entry_id);
  assert(entry);

  // Add at the front of the LRU doubly linked list
  if (cs->lru.head != INVALID_ENTRY_ID) {
    cs_entry_t *head_entry = _cs_entry_at(pkt_cache, cs->lru.head);
    assert(head_entry->lru.prev == INVALID_ENTRY_ID);
    head_entry->lru.prev = entry_id;

    entry->lru.next = cs->lru.head;
    entry->lru.prev = INVALID_ENTRY_ID;

    cs->lru.head = entry_id;
  } else { /* The list is empty */
    assert(cs->lru.tail == INVALID_ENTRY_ID);

    entry->lru.next = INVALID_ENTRY_ID;
    entry->lru.prev = INVALID_ENTRY_ID;
    cs->lru.head = cs->lru.tail = entry_id;
  }
  if (!is_update) cs->stats.lru.countAdds++;

  // Handle LRU eviction
  if (cs->num_entries > cs->max_size) {
    DEBUG("LRU eviction");
    cs->stats.lru.countLruEvictions++;

    // Remove from LRU tail
    pkt_cache_entry_t *tail = pkt_cache_entry_at(pkt_cache, cs->lru.tail);
    cs_lru_remove_entry(pkt_cache, tail);
    return LRU_EVICTION;
  }

  return LRU_SUCCESS;
}

/**
 * @brief LRU processing related to the insertion of a new entry in the content
 * store.
 * @param[in] cs Content store.
 * @param[in] entry_id Identifier of the entry in the content store entry pool.
 *
 * @return int Error code : 0 if succesful, a negative value otherwise.
 *
 * NOTE:
 *  - We insert the new element at the head of the double-linked list.
 */
static int cs_lru_add_entry(pkt_cache_t *pkt_cache, off_t entry_id) {
  return _cs_lru_add_entry(pkt_cache, entry_id, false);
}

/**
 * Move a cs_entry_t to the LRU head.
 */
static void cs_lru_update_entry(pkt_cache_t *pkt_cache,
                                pkt_cache_entry_t *entry) {
  assert(pkt_cache);
  assert(entry);

  cs_t *cs = pkt_cache_get_cs(pkt_cache);
  cs->stats.lru.countUpdates++;

  // Remove from LRU
  cs_lru_remove_entry(pkt_cache, entry);

  // Attach at the LRU head
  off_t entry_id = pkt_cache_get_entry_id(pkt_cache, entry);
  _cs_lru_add_entry(pkt_cache, entry_id, true);
}

DECLARE_CS(lru);
