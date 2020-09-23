/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * \file content_store.c
 * \brief Implementation of hICN content_store
 */

#include <inttypes.h>
#include <hicn/base/pool.h>
#include <hicn/util/log.h>

//#include <hicn/content_store/lru.h>

#include "content_store.h"

extern const cs_ops_t cs_lru;

const cs_ops_t * const cs_vft[] = {
  [CS_TYPE_LRU] = &cs_lru,
};

// XXX TODO replace by a single packet cache
// XXX TODO per cs type entry data too !
// XXX TODO getting rid of logger and the need to acquire
// XXX TODO separate cs from vft, same with strategy

#define cs_entry_from_msgbuf(entry, msgbuf)                          \
do {                                                                            \
  (entry)->hasExpiryTimeTicks = msgbuf_HasContentExpiryTime(msgbuf);            \
  if ((entry)->hasExpiryTimeTicks)                                              \
    (entry)->expiryTimeTicks = msgbuf_GetContentExpiryTimeTicks(msgbuf);        \
} while(0)

/* This is only used as a hint for first allocation, as the table is resizeable */
#define DEFAULT_CS_SIZE 64

cs_t *
_cs_create(cs_type_t type, size_t init_size, size_t max_size)
{
    if (!CS_TYPE_VALID(type)) {
        ERROR("[cs_create] Invalid content store type");
        return NULL;
    }

    if (init_size == 0)
        init_size = DEFAULT_CS_SIZE;

    cs_t * cs = malloc(sizeof(cs_t));
    if (!cs)
        return NULL;

    cs->type = type;

    // XXX TODO an entry = data + metadata specific to each policy
    pool_init(cs->entries, init_size, max_size);

    // data
    // options
    // stats


    // index by name
    cs->index_by_name = kh_init(cs_name);

#if 0
    cs->index_by_expiry_time = NULL;
    if (!cs->index_by_expiry_time) {
        ERROR("Could not create index (expiry time)");
        goto ERR_INDEX_EXPIRY;
    }
#endif

    cs_vft[type]->initialize(cs);

    return cs;
#if 0
ERR_INDEX_EXPIRY:
    free(cs);
    // XXX

    return NULL;
#endif
}

void
cs_free(cs_t * cs)
{
    cs_vft[cs->type]->finalize(cs);

#if 0
    if (cs->index_by_expiry_time)
        ; //listTimeOrdered_Release(&(store->indexByExpirationTime));
#endif
}

void cs_clear(cs_t * cs)
{
    // XXX TODO
}

off_t
cs_match(cs_t * cs, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id, uint64_t now)
{
    assert(cs);

    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    assert(msgbuf);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

    /* Lookup entry by name */
    khiter_t k = kh_get_cs_name(cs->index_by_name, msgbuf_get_name(msgbuf));
    if (k == kh_end(cs->index_by_name))
        return INVALID_MSGBUF_ID;
    cs_entry_t * entry = cs->entries + kh_val(cs->index_by_name, k);
    assert(entry);

    /* Remove any expired entry */
    if (cs_entry_has_expiry_time(entry) &&
            cs_entry_get_expiry_time(entry) < now) {
        // the entry is expired, we can remove it
        cs_remove_entry(cs, msgbuf_pool, entry);
        goto NOT_FOUND;
    }

    cs->stats.lru.countHits++;

#if 0 // XXX
    contentStoreEntry_MoveToHead(entry);
#endif

    DEBUG("CS %p LRU match %p (hits %" PRIu64 ", misses %" PRIu64 ")",
           cs, msgbuf, cs->stats.lru.countHits, cs->stats.lru.countMisses);
    return cs_entry_get_msgbuf_id(entry);

NOT_FOUND:
    cs->stats.lru.countMisses++;

    DEBUG("ContentStoreLRU %p missed msgbuf %p (hits %" PRIu64 ", misses %" PRIu64 ")",
            cs, msgbuf, cs->stats.lru.countHits, cs->stats.lru.countMisses);
    return INVALID_MSGBUF_ID;
}

// XXX temp
// XXX pool member pointer might change, not the ID.
#define msgbuf_acquire(x) (x)

cs_entry_t *
cs_add(cs_t * cs, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id, uint64_t now)
{
    assert(cs);
    assert(msgbuf_id_is_valid(msgbuf_id));

#if DEBUG
    forwarder_t * forwarder = cs_get_forwarder(cs);
    msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA);
#endif

#if 0
    // entry exists ?
    cs_entry_t *dataEntry = parcHashCodeTable_Get(data->storageByName, content);
    if(dataEntry)
        _cs_lru_purge_entry(data, dataEntry);
#endif

#if 0
    // check expiration
    uint64_t expiryTimeTicks = contentStoreEntry_MaxExpiryTime;
    if (message_HasContentExpiryTime(content))
        expiryTimeTicks = message_GetContentExpiryTimeTicks(content);

    // Don't add anything that's already expired or has exceeded RCT.
    if (now >= expiryTimeTicks)
        return false;
#endif

#if 0
    // evict
    if (data->objectCount >= data->objectCapacity)
        // Store is full. Need to make room.
        _evictByStorePolicy(data, now);
#endif

    cs_entry_t * entry = NULL;
    off_t entry_id = pool_get(cs->entries, entry);
    if (!entry)
        goto ERR_ENTRY;

    *entry = (cs_entry_t) {
        .msgbuf_id = msgbuf_id,
        .hasExpiryTimeTicks = false, // XXX
        .expiryTimeTicks = 0, // XXX
    };

    // update indices

    // update policy index
    /* eg. LRU: add new the entry at the head of the LRU */
    if (!cs_vft[cs->type]->add_entry(cs, entry_id))
        goto ERR_VFT;

#if 0
    // update expiry time index
    if (cs_entry_has_expiry_time(entry)) {
    }
#endif

#if 0
    // stats
    data->objectCount++;
    data->stats.countAdds++;
#endif

    return entry;

ERR_VFT:
    pool_put(cs->entries, entry);
ERR_ENTRY:
    return NULL;
}

int
cs_remove_entry(cs_t * cs, msgbuf_pool_t * msgbuf_pool, cs_entry_t * entry)
{
    assert(cs);
    assert(entry);

    if (cs_entry_has_expiry_time(entry))
        ; // XXX TODO listTimeOrdered_Remove(store->indexByExpirationTime, entryToPurge);

    off_t msgbuf_id = cs_entry_get_msgbuf_id(entry);

    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    khiter_t k = kh_get_cs_name(cs->index_by_name, msgbuf_get_name(msgbuf));
    if (k != kh_end(cs->index_by_name))
        kh_del(cs_name, cs->index_by_name, k);

    // This will take care of LRU entry for instance
    cs_vft[cs->type]->remove_entry(cs, entry);

    //store->objectCount--;
    pool_put(cs->entries, entry);

    return 0;
}
//
// XXX TODO what is the difference between purge and remove ?
bool
cs_remove(cs_t * cs, msgbuf_pool_t * msgbuf_pool, msgbuf_t * msgbuf)
{
    assert(cs);
    assert(msgbuf);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA);

    /* Lookup entry by name */
    khiter_t k = kh_get_cs_name(cs->index_by_name, msgbuf_get_name(msgbuf));
    if (k == kh_end(cs->index_by_name))
        return false;

    cs_entry_t * entry = cs->entries + kh_val(cs->index_by_name, k);
    assert(entry);

    cs_remove_entry(cs, msgbuf_pool, entry);
    return true;
}

