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

#ifndef _WIN32
#include <sys/queue.h>
#endif

#include <hicn/util/log.h>

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/core/content_store.h>
#include "lru.h"

// XXX TODO some part to be moved to parent

// XXX TODO
#if 0
static void _cs_lru_Log(ContentStoreInterface *storeImpl) {
    cs_lru_data_t *store =
        (cs_lru_data_t *)contentStoreInterface_GetPrivateData(storeImpl);

    logger_Log(store->logger, LoggerFacility_Processor, PARCLogLevel_All,
            __func__,
            "ContentStoreLRU @%p {count = %zu, capacity = %zu {"
            "stats = @%p {adds = %" PRIu64 ", hits = %" PRIu64
            ", misses = %" PRIu64 ", LRUEvictons = %" PRIu64
            ", ExpiryEvictions = %" PRIu64 ", RCTEvictions = %" PRIu64 "} }",
            store, store->objectCount, store->objectCapacity, &store->stats,
            store->stats.countAdds, store->stats.countHits,
            store->stats.countMisses, store->stats.countLruEvictions,
            store->stats.countExpiryEvictions, store->stats.countRCTEvictions);
}

static
bool
_cs_lru_remove_least_used(cs_t * cs)
{
    if (cs_size(cs) == 0)
        return false;

#if 0
    ListLruEntry *lruEntry = listLRU_PopTail(store->lru);
    cs_entry_t *storeEntry =
        (cs_entry_t *)listLRU_EntryGetData(lruEntry);
#else
    cs_entry_t * entry = NULL;
#endif

    DEBUG("CS %p LRU evict msgbuf %p (#evictions %" PRIu64 ")",
                cs, cs_entry_message(entry),
                cs->stats.lru.countLruEvictions);

    cs_purge_entry(cs, entry);

    return true;
}

static
void
_evictByStorePolicy(cs_t * cs, uint64_t currentTimeInTicks)
{
    // We need to make room. Here's the plan:
    //  1) Check to see if anything has expired. If so, remove it and we're done.
    //  If not, 2) Remove the least recently used item.

    cs_entry_t *entry =
        listTimeOrdered_GetOldest(store->indexByExpirationTime);
    if (entry && cs_entry_has_expiry_time(entry) &&
            (currentTimeInTicks > cs_entry_get_expiry_time(entry))) {
        // Found an expired entry. Remove it, and we're done.

        store->stats.countExpiryEvictions++;
        DEBUG("ContentStore %p evict message %p by ExpiryTime (ExpiryTime evictions %" PRIu64 ")",
                (void *)store, (void *)contentStoreEntry_GetMessage(entry),
                store->stats.countExpiryEvictions);

        _cs_lru_purge_entry(store, entry);
    } else {
        store->stats.countLruEvictions++;
        _cs_lru_remove_least_used(store);
    }
}
#endif

void
cs_lru_initialize(cs_t * cs)
{
    /* We start with an empty double-linked list */
    cs->lru.head = 0;
    cs->lru.tail = 0;
}

void
cs_lru_finalize(cs_t * cs)
{
    /* Nothing to do */
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
static
int
cs_lru_add_entry(cs_t * cs, off_t entry_id)
{
    assert(cs);

    cs_entry_t * entry = &cs->entries[entry_id];
    assert(entry);

    if (cs->lru.head != INVALID_ENTRY_ID) {
        cs_entry_t * head_entry = cs_entry_at(cs, cs->lru.head);
        assert(head_entry->lru.prev == INVALID_ENTRY_ID);
        head_entry->lru.prev = entry_id;

        entry->lru.next = cs->lru.head;
        entry->lru.prev = INVALID_ENTRY_ID;

        cs->lru.head = entry_id;
    } else {
        /* The list is empty */
        assert(cs->lru.tail == INVALID_ENTRY_ID);

        entry->lru.next = INVALID_ENTRY_ID;
        entry->lru.prev = INVALID_ENTRY_ID;
        cs->lru.head = cs->lru.tail = entry_id;
    }

    return 0;
}

/**
 * Remove a cs_entry_t from all tables and indices.
 */
static
int
cs_lru_remove_entry(cs_t * cs, cs_entry_t * entry)
{
    assert(cs);
    assert(entry);

    off_t entry_id = cs_get_entry_id(cs, entry);

    if (entry->lru.prev == INVALID_ENTRY_ID) {
        /* Not already on the head of the LRU */
        cs_entry_t * prev_entry = cs_entry_at(cs, entry->lru.prev);
        assert(prev_entry);
        prev_entry->lru.next = entry_id;
    } else {
        assert(cs->lru.head == entry_id);
    }

    return 0;
}


DECLARE_CS(lru);
