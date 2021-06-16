/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
 * The pending interest table.
 *
 * Interest aggregation strategy:
 * - The first Interest for a name is forwarded
 * - A second Interest for a name from a different reverse path may be
 * aggregated
 * - A second Interest for a name from an existing Interest is forwarded
 * - The Interest Lifetime is like a subscription time.  A reverse path entry is
 * removed once the lifetime is exceeded.
 * - Whan an Interest arrives or is aggregated, the Lifetime for that reverse
 * hop is extended.  As a simplification, we only keep a single lifetime not per
 * reverse hop.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <hicn/util/log.h>

#include "msgbuf.h"
#include "msgbuf_pool.h"
#include "ticks.h"
#include "../base/pool.h"

#include "pit.h"

// XXX TODO Should not be defined here
#define DEFAULT_INTEREST_LIFETIME 4000000000ULL

static
Ticks
_pit_calculate_lifetime(pit_t * pit, const msgbuf_t * msgbuf)
{
    uint64_t lifetime = msgbuf_get_lifetime(msgbuf);
    if (lifetime == 0)
        lifetime = NSEC_TO_TICKS(DEFAULT_INTEREST_LIFETIME);

    return ticks_now() + lifetime;
}

/* This is only used as a hint for first allocation, as the table is resizeable */
#define DEFAULT_PIT_SIZE 65535

pit_t *
_pit_create(size_t init_size, size_t max_size)
{
    pit_t * pit = malloc(sizeof(pit_t));
    if (!pit)
        return NULL;

    if (init_size == 0)
        init_size = DEFAULT_PIT_SIZE;

    pit->max_size = max_size;

    /* Initialize indices */
    pit->index_by_name = kh_init(pit_name);

    /*
     * We start by allocating a reasonably-sized pool, as this will eventually
     * be resized if needed.
     */
    pool_init(pit->entries, init_size, 0);

    return pit;
}

void
pit_free(pit_t * pit)
{
    assert(pit);

    free(pit);

    DEBUG("PIT %p destroyed", pit);
}

pit_verdict_t
pit_on_interest(pit_t * pit, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id)
{
    assert(pit);
    assert(msgbuf_id_is_valid(msgbuf_id));

    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

    fib_entry_t * fib_entry;
    Ticks expire_ts;

    /* Lookup entry by name */
    khiter_t k = kh_get_pit_name(pit->index_by_name, msgbuf_get_name(msgbuf));
    if (k == kh_end(pit->index_by_name))
        goto NOT_FOUND;
    pit_entry_t * entry = pit->entries + kh_val(pit->index_by_name, k);
    assert(entry);

    // has it expired?
    if (ticks_now() >= pit_entry_get_expire_ts(entry))
        goto TIMEOUT;

    /* Extend entry lifetime */
    expire_ts = _pit_calculate_lifetime(pit, msgbuf);
    if (expire_ts > pit_entry_get_expire_ts(entry))
        pit_entry_set_expire_ts(entry, expire_ts);

    unsigned connection_id = msgbuf_get_connection_id(msgbuf);

    // Is the reverse path already in the PIT entry?
    if (pit_entry_ingress_contains(entry, connection_id)) {
        // It is already in the PIT entry, so this is a retransmission, so
        // forward it.
        DEBUG("Message %lu existing entry (expiry %" PRIu64 ") and reverse path, forwarding",
                    msgbuf_id, pit_entry_get_expire_ts(entry));
        return PIT_VERDICT_RETRANSMIT;
    }

    // It is in the PIT but this is the first interest for the reverse path
    pit_entry_ingress_add(entry, connection_id);

    DEBUG("Message %lu existing entry (expiry %" PRIu64 ") and reverse path is new, aggregate",
            msgbuf_id, pit_entry_get_expire_ts(entry));
    return PIT_VERDICT_AGGREGATE;

TIMEOUT:
    fib_entry = pit_entry_get_fib_entry(entry);
    if (fib_entry)
        fib_entry_on_timeout(fib_entry, pit_entry_get_egress(entry));

    // it's an old entry, remove it
    k = kh_get(pit_name, pit->index_by_name, msgbuf_get_name(msgbuf));
    if (k != kh_end(pit->index_by_name))
        kh_del(pit_name, pit->index_by_name, k);

NOT_FOUND:
    /* Create PIT entry */

    expire_ts = _pit_calculate_lifetime(pit, msgbuf);

    pit_allocate(pit, entry, msgbuf);

    *entry = (pit_entry_t) {
        .msgbuf_id = msgbuf_id,
        .fib_entry = NULL,
        .create_ts = ticks_now(),
        .expire_ts = expire_ts,
    };
    pit_entry_ingress_add(entry, msgbuf_get_connection_id(msgbuf));

    DEBUG("Message %lu added to PIT (expiry %" PRIu64 ") ingress %u",
            msgbuf_id, pit_entry_get_expire_ts(entry),
            msgbuf_get_connection_id(msgbuf));

    return PIT_VERDICT_FORWARD;
}

nexthops_t *
pit_on_data(pit_t * pit, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id)
{
    assert(pit);
    assert(msgbuf_id_is_valid(msgbuf_id));

    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA);

    nexthops_t * nexthops = NULL;

    /* Lookup entry by name */
    khiter_t k = kh_get_pit_name(pit->index_by_name, msgbuf_get_name(msgbuf));
    if (k == kh_end(pit->index_by_name))
        goto NOT_FOUND;

    pit_entry_t * entry = pit->entries + kh_val(pit->index_by_name, k);
    assert(entry);

    // here we need to check if the PIT entry is expired
    // if so, remove the PIT entry.
    Ticks now = ticks_now();
    if (now >= pit_entry_get_expire_ts(entry))
        goto TIMEOUT;

    /* PIT entry is not expired, use it */
    fib_entry_t * fib_entry = pit_entry_get_fib_entry(entry);
    if (fib_entry)
        fib_entry_on_data(fib_entry, pit_entry_get_egress(entry),
                msgbuf, pit_entry_get_create_ts(entry), ticks_now());

    // XXX TODO : be sure nexthops are valid b/c pit entry is removed
    // XXX TODO eventually pass holding structure as parameter
    nexthops = pit_entry_get_ingress(entry);

TIMEOUT:
    /* Remove entry from PIT */
    kh_del(pit_name, pit->index_by_name, k);

NOT_FOUND:
    return nexthops;
}

void
pit_remove(pit_t * pit, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id)
{
    assert(pit);
    assert(msgbuf_id_is_valid(msgbuf_id));

    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    assert(msgbuf);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

    khiter_t k = kh_get(pit_name, pit->index_by_name, msgbuf_get_name(msgbuf));
    if (k == kh_end(pit->index_by_name))
        return;
    //off_t index = kh_val(pit->index_by_name, k);
    //pit_entry_t * entry = pit_at(pit, index);
    kh_del(pit_name, pit->index_by_name, k);

    DEBUG("Message %p removed from PIT", msgbuf);
}

pit_entry_t *
pit_lookup(const pit_t * pit, const msgbuf_t * interest_msgbuf)
{
    assert(pit);
    assert(interest_msgbuf);
    assert(msgbuf_get_type(interest_msgbuf) == MSGBUF_TYPE_INTEREST);

    khiter_t k = kh_get(pit_name, pit->index_by_name,
            msgbuf_get_name(interest_msgbuf));
    if (k == kh_end(pit->index_by_name))
        return NULL;
    off_t index = kh_val(pit->index_by_name, k);
    pit_entry_t * entry = pit_at(pit, index);
    assert(entry);

    return entry;
}
