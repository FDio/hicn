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
static void _content_store_lru_Log(ContentStoreInterface *storeImpl) {
    content_store_lru_data_t *store =
        (content_store_lru_data_t *)contentStoreInterface_GetPrivateData(storeImpl);

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
_content_store_lru_remove_least_used(content_store_t * cs)
{
    if (content_store_size(cs) == 0)
        return false;

#if 0
    ListLruEntry *lruEntry = listLRU_PopTail(store->lru);
    content_store_entry_t *storeEntry =
        (content_store_entry_t *)listLRU_EntryGetData(lruEntry);
#else
    content_store_entry_t * entry = NULL;
#endif

    DEBUG("CS %p LRU evict msgbuf %p (#evictions %" PRIu64 ")",
                cs, content_store_entry_message(entry),
                cs->stats.lru.countLruEvictions);

    content_store_purge_entry(cs, entry);

    return true;
}

static
void
_evictByStorePolicy(content_store_t * cs, uint64_t currentTimeInTicks)
{
    // We need to make room. Here's the plan:
    //  1) Check to see if anything has expired. If so, remove it and we're done.
    //  If not, 2) Remove the least recently used item.

    content_store_entry_t *entry =
        listTimeOrdered_GetOldest(store->indexByExpirationTime);
    if (entry && content_store_entry_has_expiry_time(entry) &&
            (currentTimeInTicks > content_store_entry_get_expiry_time(entry))) {
        // Found an expired entry. Remove it, and we're done.

        store->stats.countExpiryEvictions++;
        DEBUG("ContentStore %p evict message %p by ExpiryTime (ExpiryTime evictions %" PRIu64 ")",
                (void *)store, (void *)contentStoreEntry_GetMessage(entry),
                store->stats.countExpiryEvictions);

        _content_store_lru_purge_entry(store, entry);
    } else {
        store->stats.countLruEvictions++;
        _content_store_lru_remove_least_used(store);
    }
}
#endif

void
content_store_lru_initialize(content_store_t * cs)
{
    content_store_lru_data_t * data = cs->data;

    data->lru = NULL;
    if (!data->lru) {
        ERROR("Could not create LRU index");
        goto ERR_INDEX;
    }

ERR_INDEX:
    return;
}

void
content_store_lru_finalize(content_store_t * cs)
{
    content_store_lru_data_t * data = cs->data;

    if (data->lru != NULL)
        ; // XXX TODO listLRU_Destroy(&(store->lru));
}

bool
content_store_lru_add_entry(content_store_t * cs, content_store_entry_t * entry)
{
    assert(cs);
    assert(entry);

    if (content_store_size(cs) == 0)
        return false;
#if 0
    content_store_lru_data_t * data = cs->data;

    content_store_entry_t *dataEntry = parcHashCodeTable_Get(data->storageByName, content);
    if(dataEntry)
        _content_store_lru_purge_entry(data, dataEntry);

    uint64_t expiryTimeTicks = contentStoreEntry_MaxExpiryTime;
    if (message_HasContentExpiryTime(content))
        expiryTimeTicks = message_GetContentExpiryTimeTicks(content);

    // Don't add anything that's already expired or has exceeded RCT.
    if (now >= expiryTimeTicks)
        return false;

    if (data->objectCount >= data->objectCapacity)
        // Store is full. Need to make room.
        _evictByStorePolicy(data, now);

    // And now add a new entry to the head of the LRU.
    content_store_entry_t *entry = contentStoreEntry_Create(content, data->lru);
    if (!entry)
        return false;

    if (!parcHashCodeTable_Add(data->storageByName, content, entry)) {
        // Free what we just created, but did not add. 'entry' has ownership of
        // 'copy', and so will call _Release() on it
        contentStoreEntry_Release(&entry);
        WARN("ContentStoreLRU %p failed to add message %p to hash table",
                (void *)data, (void *)content);
        return false;
    }

    if (content_store_entry_has_expiry_time(entry))
        listTimeOrdered_Add(data->indexByExpirationTime, entry);

    data->objectCount++;
    data->stats.countAdds++;

    DEBUG("ContentStoreLRU %p saved message %p (object count %" PRIu64 ")",
            data, msgbuf, content_store_size(cs));
#endif
    return true;
}

/**
 * Remove a content_store_entry_t from all tables and indices.
 */
static
void
content_store_lru_remove_entry(content_store_t * cs, content_store_entry_t * entry)
{
    assert(cs);
    assert(entry);
    //
    // XXX REMOVE ENTRY FROM LRU
}


DECLARE_CONTENT_STORE(lru);
