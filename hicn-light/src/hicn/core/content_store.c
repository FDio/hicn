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

extern const content_store_ops_t content_store_lru;

const content_store_ops_t * const content_store_vft[] = {
  [CONTENT_STORE_TYPE_LRU] = &content_store_lru,
};

// XXX TODO replace by a single packet cache
// XXX TODO per cs type entry data too !
// XXX TODO getting rid of logger and the need to acquire
// XXX TODO separate cs from vft, same with strategy

#define content_store_entry_from_msgbuf(entry, msgbuf)                          \
do {                                                                            \
  (entry)->hasExpiryTimeTicks = msgbuf_HasContentExpiryTime(msgbuf);            \
  if ((entry)->hasExpiryTimeTicks)                                              \
    (entry)->expiryTimeTicks = msgbuf_GetContentExpiryTimeTicks(msgbuf);        \
} while(0)

/* This is only used as a hint for first allocation, as the table is resizeable */
#define DEFAULT_CONTENT_STORE_SIZE 64

content_store_t *
_content_store_create(content_store_type_t type, size_t init_size, size_t max_size)
{
    if (!CONTENT_STORE_TYPE_VALID(type)) {
        ERROR("[content_store_create] Invalid content store type");
        return NULL;
    }

    if (init_size == 0)
        init_size = DEFAULT_CONTENT_STORE_SIZE;

    content_store_t * cs = malloc(sizeof(content_store_t));
    if (!cs)
        return NULL;

    cs->max_size = max_size;
    cs->type = type;

    // XXX TODO an entry = data + metadata specific to each policy
    pool_init(cs->entries, init_size);

    // data
    // options
    // stats


    // index by name
    cs->index_by_name = kh_init(cs_name);

    cs->index_by_expiry_time = NULL;
    if (!cs->index_by_expiry_time) {
        ERROR("Could not create index (expiry time)");
        goto ERR_INDEX_EXPIRY;
    }


    // XXX indices specific to each policy => vft
    // index by expiration time
    // lru ?

    content_store_vft[type]->initialize(cs);

ERR_INDEX_EXPIRY:
    free(cs);
    // XXX

    return NULL;
}

void
content_store_free(content_store_t * cs)
{
    content_store_vft[cs->type]->finalize(cs);

    if (cs->index_by_expiry_time)
        ; //listTimeOrdered_Release(&(store->indexByExpirationTime));
}

void content_store_clear(content_store_t * cs)
{
    // XXX TODO
}

msgbuf_t *
content_store_match(content_store_t * cs, msgbuf_t * msgbuf, uint64_t now)
{
    assert(cs);
    assert(msgbuf);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

    /* Lookup entry by name */
    khiter_t k = kh_get_cs_name(cs->index_by_name, msgbuf_get_name(msgbuf));
    if (k == kh_end(cs->index_by_name))
        return NULL;
    content_store_entry_t * entry = cs->entries + kh_val(cs->index_by_name, k);
    assert(entry);

    /* Remove any expired entry */
    if (content_store_entry_has_expiry_time(entry) &&
            content_store_entry_expiry_time(entry) < now) {
        // the entry is expired, we can remove it
        content_store_remove_entry(cs, entry);
        goto NOT_FOUND;
    }

    cs->stats.lru.countHits++;

#if 0 // XXX
    contentStoreEntry_MoveToHead(entry);
#endif

    DEBUG("CS %p LRU match %p (hits %" PRIu64 ", misses %" PRIu64 ")",
           cs, msgbuf, cs->stats.lru.countHits, cs->stats.lru.countMisses);
    return content_store_entry_message(entry);

NOT_FOUND:
    cs->stats.lru.countMisses++;

    DEBUG("ContentStoreLRU %p missed msgbuf %p (hits %" PRIu64 ", misses %" PRIu64 ")",
            cs, msgbuf, cs->stats.lru.countHits, cs->stats.lru.countMisses);
    return NULL;
}

void
content_store_add(content_store_t * cs, msgbuf_t * msgbuf, uint64_t now)
{
    assert(cs);
    assert(msgbuf);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA);

    content_store_entry_t * entry = NULL;

    /* borrow from content_store_lru_add_entry */

    content_store_vft[cs->type]->add_entry(cs, entry);
}

void
content_store_remove_entry(content_store_t * cs, content_store_entry_t * entry)
{
    assert(cs);
    assert(entry);

    if (content_store_entry_has_expiry_time(entry))
        ; // XXX TODO listTimeOrdered_Remove(store->indexByExpirationTime, entryToPurge);

    msgbuf_t * msgbuf = content_store_entry_message(entry);
    khiter_t k = kh_get_cs_name(cs->index_by_name, msgbuf_get_name(msgbuf));
    if (k != kh_end(cs->index_by_name))
        kh_del(cs_name, cs->index_by_name, k);

    // This will take care of LRU entry for instance
    content_store_vft[cs->type]->remove_entry(cs, entry);

    //store->objectCount--;
    pool_put(cs->entries, entry);

}
//
// XXX TODO what is the difference between purge and remove ?
bool
content_store_remove(content_store_t * cs, msgbuf_t * msgbuf)
{
    assert(cs);
    assert(msgbuf);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA);

    /* Lookup entry by name */
    khiter_t k = kh_get_cs_name(cs->index_by_name, msgbuf_get_name(msgbuf));
    if (k == kh_end(cs->index_by_name))
        return false;

    content_store_entry_t * entry = cs->entries + kh_val(cs->index_by_name, k);
    assert(entry);

    content_store_remove_entry(cs, entry);
    return true;
}

