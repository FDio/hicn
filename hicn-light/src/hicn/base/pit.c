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
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <hicn/base/msgbuf.h>
#include <hicn/base/pool.h>
#include <hicn/core/ticks.h>
#include <hicn/util/log.h>

#include "pit.h"

// XXX TODO Should not be defined here
#define DEFAULT_INTEREST_LIFETIME 4000000000ULL

static Ticks _pit_calculate_lifetime(pit_t * pit,
        msgbuf_t *interest_msgbuf) {
    uint64_t interestLifetimeTicks =
        msgbuf_get_interest_lifetime(interest_msgbuf);
    if (interestLifetimeTicks == 0) {
        interestLifetimeTicks = NSEC_TO_TICKS(DEFAULT_INTEREST_LIFETIME);
    }

    Ticks expiry_time = ticks_now() + interestLifetimeTicks;
    return expiry_time;
}

// max_elts default is 65535
pit_t *
pit_create(size_t max_elts)
{
    pit_t * pit = malloc(sizeof(pit_t));
    if (!pit)
        return NULL;

    pool_init(pit->entries, max_elts);
    pit->index_by_name = kh_init(pit_name);

    DEBUG("PIT %p created", pit);

    return pit;
}

void
pit_free(pit_t * pit)
{
    assert(pit);
    // XXX TODO

    DEBUG("PIT %p destroyed", pit);
}

pit_verdict_t
pit_on_interest(pit_t * pit, msgbuf_t * interest_msgbuf)
{
    assert(pit);
    assert(interest_msgbuf);
    assert(msgbuf_get_type(interest_msgbuf) == MESSAGE_TYPE_INTEREST);

    fib_entry_t * fib_entry;
    Ticks expiry_time;

    /* Lookup entry by name */
    khiter_t k = kh_get_pit_name(pit->index_by_name, msgbuf_get_name(interest_msgbuf));
    if (k == kh_end(pit->index_by_name))
        goto NOT_FOUND;
    pit_entry_t * entry = pit->entries + kh_val(pit->index_by_name, k);
    assert(entry);

    // has it expired?
    if (ticks_now() >= pit_entry_get_expiry_time(entry))
        goto TIMEOUT;

    /* Extend entry lifetime */
    expiry_time = _pit_calculate_lifetime(pit, interest_msgbuf);
    if (expiry_time > pit_entry_get_expiry_time(entry))
        pit_entry_set_expiry_time(entry, expiry_time);

    unsigned connection_id = msgbuf_get_connection_id(interest_msgbuf);

    // Is the reverse path already in the PIT entry?
    if (pit_entry_ingress_contains(entry, connection_id)) {
        // It is already in the PIT entry, so this is a retransmission, so
        // forward it.
        DEBUG("Message %p existing entry (expiry %" PRIu64 ") and reverse path, forwarding",
                    interest_msgbuf, pit_entry_get_expiry_time(entry));
        return PIT_VERDICT_RETRANSMIT;
    }

    // It is in the PIT but this is the first interest for the reverse path
    pit_entry_ingress_add(entry, connection_id);

    DEBUG("Message %p existing entry (expiry %" PRIu64 ") and reverse path is new, aggregate",
            interest_msgbuf, pit_entry_get_expiry_time(entry));
    return PIT_VERDICT_AGGREGATE;

TIMEOUT:
    fib_entry = pit_entry_get_fib_entry(entry);
    if (fib_entry)
        fib_entry_on_timeout(fib_entry, pit_entry_get_egress(entry));

    // it's an old entry, remove it
    k = kh_get(pit_name, pit->index_by_name, msgbuf_get_name(interest_msgbuf));
    if (k != kh_end(pit->index_by_name))
        kh_del(pit_name, pit->index_by_name, k);

NOT_FOUND:
    /* Create PIT entry */

    expiry_time = _pit_calculate_lifetime(pit, interest_msgbuf);

    pit_allocate(pit, entry, interest_msgbuf);
    pit_entry_from_msgbuf(entry, interest_msgbuf, expiry_time, ticks_now());

    DEBUG("Message %p added to PIT (expiry %" PRIu64 ") ingress %u",
            interest_msgbuf, pit_entry_get_expiry_time(entry),
            msgbuf_get_connection_id(interest_msgbuf));

    return PIT_VERDICT_FORWARD;
}

nexthops_t *
pit_on_data(pit_t * pit, const msgbuf_t * data_msgbuf)
{
    assert(pit);
    assert(data_msgbuf);
    assert(msgbuf_get_type(data_msgbuf) == MESSAGE_TYPE_DATA);

    nexthops_t * nexthops = NULL;

    /* Lookup entry by name */
    khiter_t k = kh_get_pit_name(pit->index_by_name, msgbuf_get_name(data_msgbuf));
    if (k == kh_end(pit->index_by_name))
        goto NOT_FOUND;

    pit_entry_t * entry = pit->entries + kh_val(pit->index_by_name, k);
    assert(entry);

    // here we need to check if the PIT entry is expired
    // if so, remove the PIT entry.
    Ticks now = ticks_now();
    if (now >= pit_entry_get_expiry_time(entry))
        goto TIMEOUT;

    /* PIT entry is not expired, use it */
    fib_entry_t * fib_entry = pit_entry_get_fib_entry(entry);
    if (fib_entry)
        fib_entry_on_data(fib_entry, pit_entry_get_egress(entry),
                data_msgbuf, pit_entry_get_creation_time(entry), ticks_now());

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
pit_remove(pit_t * pit, const msgbuf_t * interest_msgbuf)
{
    assert(pit);
    assert(interest_msgbuf);
    assert(msgbuf_get_type(interest_msgbuf) == MESSAGE_TYPE_INTEREST);

    khiter_t k = kh_get(pit_name, pit->index_by_name, msgbuf_get_name(interest_msgbuf));
    if (k == kh_end(pit->index_by_name))
        return;
    //off_t index = kh_val(pit->index_by_name, k);
    //pit_entry_t * entry = pit_at(pit, index);
    kh_del(pit_name, pit->index_by_name, k);

    DEBUG("Message %p removed from PIT", interest_msgbuf);
}

pit_entry_t *
pit_lookup(const pit_t * pit, const msgbuf_t * interest_msgbuf)
{
    assert(pit);
    assert(interest_msgbuf);
    assert(msgbuf_get_type(interest_msgbuf) == MESSAGE_TYPE_INTEREST);

    khiter_t k = kh_get(pit_name, pit->index_by_name,
            msgbuf_get_name(interest_msgbuf));
    if (k == kh_end(pit->index_by_name))
        return NULL;
    off_t index = kh_val(pit->index_by_name, k);
    pit_entry_t * entry = pit_at(pit, index);
    assert(entry);

    return entry;
}
