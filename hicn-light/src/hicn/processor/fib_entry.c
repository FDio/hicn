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

#include <hicn/hicn-light/config.h>
#include <stdio.h>

#include <hicn/processor/fib_entry.h>

#include <hicn/core/nameBitvector.h>

#include <hicn/base/strategy_vft.h>
#ifdef WITH_MAPME
#include <parc/algol/parc_HashMap.h>
#include <hicn/core/ticks.h>
#endif /* WITH_MAPME */

#include <parc/algol/parc_Memory.h>
#include <parc/assert/parc_Assert.h>

#include <hicn/utils/commands.h>
#include <hicn/core/connectionState.h>

#ifdef WITH_POLICY
#include <hicn/core/forwarder.h>
#include <hicn/policy.h>

#ifdef WITH_MAPME
#include <hicn/core/mapme.h>
#endif /* WITH_MAPME */

#endif /* WITH_POLICY */

#ifdef WITH_PREFIX_STATS
#include <hicn/base/prefix_stats.h>
#endif /* WITH_PREFIX_STATS */


fib_entry_t *
fib_entry_Create(Name *name, strategy_type_t strategy_type,
        strategy_options_t * strategy_options, const Forwarder * forwarder)
{
    fib_entry_t *fib_entry = parcMemory_AllocateAndClear(sizeof(fib_entry_t));
    parcAssertNotNull(fib_entry, "parcMemory_AllocateAndClear(%zu) returned NULL",
            sizeof(fib_entry_t));
    fib_entry->name = name_Acquire(name);

    fib_entry_SetStrategy(fib_entry, strategy_type, strategy_options);

    fib_entry->refcount = 1;

#ifdef WITH_MAPME
    fib_entry->userData = NULL;
    fib_entry->userDataRelease = NULL;
#endif /* WITH_MAPME */

    fib_entry->forwarder = forwarder;

#ifdef WITH_POLICY
    fib_entry->policy = POLICY_NONE;
#endif /* WITH_POLICY */

#ifdef WITH_PREFIX_STATS
    fib_entry->prefix_stats = PREFIX_STATS_EMPTY;
    fib_entry->prefix_counters = PREFIX_COUNTERS_EMPTY;
#endif /* WITH_PREFIX_STATS */

    return fib_entry;
}

fib_entry_t *
fib_entry_Acquire(const fib_entry_t *fib_entry)
{
    parcAssertNotNull(fib_entry, "Parameter fib_entry must be non-null");
    fib_entry_t *copy = (fib_entry_t *)fib_entry;
    copy->refcount++;
    return copy;
}

void
fib_entry_Release(fib_entry_t **fib_entryPtr) {
    fib_entry_t *fib_entry = *fib_entryPtr;
    parcAssertTrue(fib_entry->refcount > 0, "Illegal state: refcount is 0");
    fib_entry->refcount--;
    if (fib_entry->refcount == 0) {
        name_Release(&fib_entry->name);
#ifdef WITH_MAPME
        if (fib_entry->userData) {
            fib_entry->userDataRelease(&fib_entry->userData);
        }
#endif /* WITH_MAPME */
        parcMemory_Deallocate((void **)&fib_entry);
    }
    *fib_entryPtr = NULL;
}

// XXX TODO DUPLICATE
void
fib_entry_SetStrategy(fib_entry_t *fib_entry, strategy_type_t strategy_type,
        strategy_options_t * strategy_options)
{
    if (STRATEGY_TYPE_VALID(strategy_type)) {
        fib_entry->strategy.type = strategy_type;
        if (strategy_options)
            fib_entry->strategy.options = *strategy_options;
        strategy_vft[strategy_type]->initialize(&fib_entry->strategy);
    }
}

#ifdef WITH_POLICY

nexthops_t *
fib_entry_filter_nexthops(fib_entry_t * fib_entry, nexthops_t * nexthops,
        unsigned ingress_id, bool prefer_local)
{
    /* Filter out ingress, down & administrative down faces */
    connection_table_t * table = forwarder_GetConnectionTable(fib_entry->forwarder);
    Connection * conn = NULL; // XXX
    unsigned nexthop, i;
    uint_fast32_t flags;

    policy_t policy = fib_entry_GetPolicy(fib_entry);

    nexthops_enumerate(nexthops, i, nexthop, {
        conn = connection_table_at(table, nexthop);
        nexthops_disable_if(nexthops, i, nexthop == ingress_id);
        nexthops_disable_if(nexthops, i,
                (connection_GetAdminState(conn) == CONNECTION_STATE_DOWN));
        nexthops_disable_if(nexthops, i,
                (connection_GetState(conn) == CONNECTION_STATE_DOWN));
    });

    if (prefer_local) {
        /* Backup flags */
        flags = nexthops->flags;

        /* Filter local */
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i, (!connection_IsLocal(conn)));
        });

        /* Local faces have priority */
        if (nexthops_curlen(nexthops) > 0)
            return nexthops;

        nexthops->flags = flags;
    }

    /* Filter out local */
    nexthops_enumerate(nexthops, i, nexthop, {
        conn = connection_table_at(table, nexthop);
        nexthops_disable_if(nexthops, i, (connection_IsLocal(conn)));

        /* Policy filtering : next hops */
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_REQUIRE) &&
                (!connection_HasTag(conn, POLICY_TAG_WIRED)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_PROHIBIT) &&
                (connection_HasTag(conn, POLICY_TAG_WIRED)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_REQUIRE) &&
                (!connection_HasTag(conn, POLICY_TAG_WIFI)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_PROHIBIT) &&
                (connection_HasTag(conn, POLICY_TAG_WIFI)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_REQUIRE) &&
                (!connection_HasTag(conn, POLICY_TAG_CELLULAR)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_PROHIBIT) &&
                (connection_HasTag(conn, POLICY_TAG_CELLULAR)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE) &&
                (!connection_HasTag(conn, POLICY_TAG_TRUSTED)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_PROHIBIT) &&
                (connection_HasTag(conn, POLICY_TAG_TRUSTED)));
    });

    if (nexthops_curlen(nexthops) == 0)
        return nexthops;

    /* We have at least one matching next hop, implement heuristic */

    /*
     * As VPN connections might trigger duplicate uses of one interface, we start
     * by filtering out interfaces based on trust status.
     */
    flags = nexthops->flags;

    if ((policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE) ||
            (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_PREFER)) {

        /* Try to filter out NON TRUSTED faces */
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    (!connection_HasTag(conn, POLICY_TAG_TRUSTED)));
        });

        if ((nexthops_curlen(nexthops) == 0) && (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE)) {
            return nexthops;
        }

    } else {
        /* Try to filter out TRUSTED faces */
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    (connection_HasTag(conn, POLICY_TAG_TRUSTED)));
        });
    }

    if (nexthops_curlen(nexthops) == 0)
        nexthops->flags = flags;

    /* Other preferences */
    if (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_AVOID) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    connection_HasTag(conn, POLICY_TAG_WIRED));
        });
        if (nexthops_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }
    if (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_AVOID) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    connection_HasTag(conn, POLICY_TAG_WIFI));
        });
        if (nexthops_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }
    if (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_AVOID) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    connection_HasTag(conn, POLICY_TAG_CELLULAR));
        });
        if (nexthops_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }

    if (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_PREFER) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    !connection_HasTag(conn, POLICY_TAG_WIRED));
        });
        if (nexthops_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }
    if (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_PREFER) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    !connection_HasTag(conn, POLICY_TAG_WIFI));
        });
        if (nexthops_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }
    if (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_PREFER) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    !connection_HasTag(conn, POLICY_TAG_CELLULAR));
        });
        if (nexthops_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }

    /* Priority */
    uint32_t max_priority = 0;
    nexthops_foreach(nexthops, nexthop, {
        conn = connection_table_at(table, nexthop);
        uint32_t priority = connection_GetPriority(conn);
        if (priority > max_priority)
            max_priority = priority;
    });
    nexthops_enumerate(nexthops, i, nexthop, {
        conn = connection_table_at(table, nexthop);
        nexthops_disable_if(nexthops, i,
                connection_GetPriority(conn) < max_priority);
    });

    return nexthops;
}

/*
 * Update available next hops following policy update.
 *
 * The last nexthop parameter is only used if needed, otherwise the pointer to
 * fib entry is returned to avoid an useless copy
 */
nexthops_t *
fib_entry_GetAvailableNextHops(fib_entry_t *fib_entry, unsigned in_connection, nexthops_t * new_nexthops)
{
    connection_table_t * table = forwarder_GetConnectionTable(fib_entry->forwarder);

    /*
     * Give absolute preference to local faces, with no policy, unless
     * in_connection == ~0, which means we are searching faces on which to
     * advertise our prefix
     */
    if (in_connection == ~0) {
        /* We create a nexthop structure based on connections */
        // XXX This should be done close to where it is needed
        Connection ** conn_ptr;
        connection_table_foreach(table, conn_ptr, {
            new_nexthops->elts[nexthops_len(new_nexthops)] = connection_table_get_connection_id(table, conn_ptr);
            nexthops_inc(new_nexthops);
        });

        return fib_entry_filter_nexthops(fib_entry, new_nexthops, in_connection, false);
    }

    return fib_entry_filter_nexthops(fib_entry, fib_entry_nexthops(fib_entry), in_connection, true);
}

policy_t
fib_entry_GetPolicy(const fib_entry_t *fib_entry)
{
    return fib_entry->policy;
}

void
fib_entry_SetPolicy(fib_entry_t *fib_entry, policy_t policy)
{
    fib_entry->policy = policy;
    mapme_reconsiderfib_entry_t(forwarder_getMapmeInstance(fib_entry->forwarder), fib_entry);
}

#endif /* WITH_POLICY */

void
fib_entry_nexthops_add(fib_entry_t * fib_entry, unsigned nexthop)
{
    nexthops_add(fib_entry_nexthops(fib_entry), nexthop);
    // XXX TODO
    strategy_vft[fib_entry->strategy.type]->add_nexthop(&fib_entry->strategy, nexthop, NULL);
}

void
fib_entry_nexthops_remove(fib_entry_t * fib_entry, unsigned nexthop)
{
    nexthops_remove(fib_entry_nexthops(fib_entry), nexthop);
    // XXX TODO
    strategy_vft[fib_entry->strategy.type]->remove_nexthop(&fib_entry->strategy, nexthop, NULL);
}

const nexthops_t *
fib_entry_GetNexthopsFromForwardingStrategy( fib_entry_t *fib_entry,
        const msgbuf_t * msgbuf, bool is_retransmission)
{
    parcAssertNotNull(fib_entry, "Parameter fib_entry must be non-null");

    const prefix_stats_mgr_t * mgr = forwarder_GetPrefixStatsMgr(fib_entry->forwarder);

    /* Filtering */
    nexthops_t new_nexthops;
    nexthops_t * nexthops = fib_entry_GetAvailableNextHops(fib_entry,
            msgbuf_connection_id(msgbuf), &new_nexthops);
    if (nexthops_curlen(nexthops) == 0)
        return nexthops;

#ifdef WITH_PREFIX_STATS
    /*
     * Update statistics about loss rates. We only detect losses upon
     * retransmissions, and assume for the computation that the candidate set of
     * output faces is the same as previously (i.e. does not take into account
     * event such as face up/down, policy update, etc. Otherwise we would need to
     * know what was the previous choice !
     */
    if (is_retransmission)
        prefix_stats_on_retransmission(mgr, &fib_entry->prefix_counters, nexthops);
#endif /* WITH_PREFIX_STATS */

    /*
     * NOTE: We might want to call a forwarding strategy even with no nexthop to
     * take a fallback decision.
     */
    if (nexthops_curlen(nexthops) == 0)
        return nexthops;

#ifdef WITH_POLICY
    /*
     * If multipath is disabled, we don't offer much choice to the forwarding
     * strategy, but still go through it for accounting purposes.
     */
    policy_t policy = fib_entry_GetPolicy(fib_entry);
    if ((policy.tags[POLICY_TAG_MULTIPATH].state == POLICY_STATE_PROHIBIT) ||
            (policy.tags[POLICY_TAG_MULTIPATH].state != POLICY_STATE_AVOID)) {
        nexthops_select_one(nexthops);
    }
#endif /* WITH_POLICY */

    return strategy_vft[fib_entry->strategy.type]->lookup_nexthops(&fib_entry->strategy,
            nexthops, msgbuf);
}

void
fib_entry_ReceiveObjectMessage(fib_entry_t *fib_entry,
        const nexthops_t * nexthops, const msgbuf_t * msgbuf,
        Ticks pitEntryCreation, Ticks objReception)
{
    parcAssertNotNull(fib_entry, "Parameter fib_entry must be non-null");

#ifdef WITH_PREFIX_STATS
    const prefix_stats_mgr_t * mgr = forwarder_GetPrefixStatsMgr(fib_entry->forwarder);
    Ticks rtt = objReception - pitEntryCreation;
    prefix_stats_on_data(mgr, &fib_entry->prefix_stats, &fib_entry->prefix_counters,
            nexthops, msgbuf, rtt);
#endif /* WITH_PREFIX_STATS */

    strategy_vft[fib_entry->strategy.type]->on_data(&fib_entry->strategy, nexthops, msgbuf, pitEntryCreation, objReception);
}

void
fib_entry_OnTimeout(fib_entry_t *fib_entry, const nexthops_t * nexthops)
{
    parcAssertNotNull(fib_entry, "Parameter fib_entry must be non-null");

#ifdef WITH_PREFIX_STATS
    const prefix_stats_mgr_t * mgr = forwarder_GetPrefixStatsMgr(fib_entry->forwarder);
    prefix_stats_on_timeout(mgr, &fib_entry->prefix_counters, nexthops);
#endif /* WITH_PREFIX_STATS */

    strategy_vft[fib_entry->strategy.type]->on_timeout(&fib_entry->strategy, nexthops);
}

Name *fib_entry_GetPrefix(const fib_entry_t *fib_entry) {
    parcAssertNotNull(fib_entry, "Parameter fib_entry must be non-null");
    return fib_entry->name;
    // return metisName_Acquire(fib_entry->name);
}

#ifdef WITH_MAPME

void *fib_entry_getUserData(const fib_entry_t *fib_entry) {
    parcAssertNotNull(fib_entry, "Parameter fib_entry must be non-null");
    return fib_entry->userData;
}

void fib_entry_setUserData(fib_entry_t *fib_entry, const void *userData,
        void (*userDataRelease)(void **)) {
    parcAssertNotNull(fib_entry, "Parameter fib_entry must be non-null");
    fib_entry->userData = (void *)userData;
    fib_entry->userDataRelease = userDataRelease;
}

#endif /* WITH_MAPME */
