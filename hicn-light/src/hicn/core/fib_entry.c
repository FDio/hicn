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

#include <stdio.h>

#include <hicn/hicn-light/config.h>
#include <hicn/core/fib_entry.h>
//#include <hicn/core/connectionState.h>
#include <hicn/base/strategy_vft.h>
#include <hicn/core/nameBitvector.h>
#include <hicn/utils/commands.h>

#ifdef WITH_MAPME
#include <hicn/core/ticks.h>
#endif /* WITH_MAPME */

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
fib_entry_create(Name *name, strategy_type_t strategy_type,
        strategy_options_t * strategy_options, const forwarder_t * forwarder)
{

    assert(name);
    assert(forwarder);

    fib_entry_t * entry = malloc(sizeof(fib_entry_t));
    if (!entry)
        goto ERR_MALLOC;

    entry->name = name_Acquire(name);

    // XXX TODO strategy type might be undefined. We need a default strategy
    // specified somewhere in the configuration.
    fib_entry_set_strategy(entry, strategy_type, strategy_options);

#ifdef WITH_MAPME
    entry->user_data = NULL;
    entry->user_data_release = NULL;
#endif /* WITH_MAPME */

    entry->forwarder = forwarder;

#ifdef WITH_POLICY
    entry->policy = POLICY_NONE;
#endif /* WITH_POLICY */

#ifdef WITH_PREFIX_STATS
    entry->prefix_stats = PREFIX_STATS_EMPTY;
    entry->prefix_counters = PREFIX_COUNTERS_EMPTY;
#endif /* WITH_PREFIX_STATS */

    return entry;

ERR_MALLOC:
    return NULL;
}

void
fib_entry_free(fib_entry_t * entry)
{
    assert(entry);

    name_Release(&entry->name);
#ifdef WITH_MAPME
    if (entry->user_data)
        entry->user_data_release(&entry->user_data);
#endif /* WITH_MAPME */
    free(entry);
}

// XXX TODO DUPLICATE
void
fib_entry_set_strategy(fib_entry_t * entry, strategy_type_t strategy_type,
        strategy_options_t * strategy_options)
{
    if (STRATEGY_TYPE_VALID(strategy_type)) {
        entry->strategy.type = strategy_type;
        if (strategy_options)
            entry->strategy.options = *strategy_options;
        strategy_vft[strategy_type]->initialize(&entry->strategy);
    }
}

#ifdef WITH_POLICY

nexthops_t *
fib_entry_filter_nexthops(fib_entry_t * entry, nexthops_t * nexthops,
        unsigned ingress_id, bool prefer_local)
{
    assert(entry);
    assert(nexthops);

    /* Filter out ingress, down & administrative down faces */
    const connection_table_t * table = forwarder_get_connection_table(entry->forwarder);
    connection_t * conn;
    unsigned nexthop, i;
    uint_fast32_t flags;

    policy_t policy = fib_entry_get_policy(entry);

    nexthops_enumerate(nexthops, i, nexthop, {
        conn = connection_table_at(table, nexthop);
        nexthops_disable_if(nexthops, i, nexthop == ingress_id);
        nexthops_disable_if(nexthops, i,
                (connection_get_admin_state(conn) == FACE_STATE_DOWN));
        nexthops_disable_if(nexthops, i,
                (connection_get_state(conn) == FACE_STATE_DOWN));
    });

    if (prefer_local) {
        /* Backup flags */
        flags = nexthops->flags;

        /* Filter local */
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i, (!connection_is_local(conn)));
        });

        /* Local faces have priority */
        if (nexthops_get_curlen(nexthops) > 0)
            return nexthops;

        nexthops->flags = flags;
    }

    /* Filter out local */
    nexthops_enumerate(nexthops, i, nexthop, {
        conn = connection_table_at(table, nexthop);
        nexthops_disable_if(nexthops, i, (connection_is_local(conn)));

        /* Policy filtering : next hops */
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_REQUIRE) &&
                (!connection_has_tag(conn, POLICY_TAG_WIRED)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_PROHIBIT) &&
                (connection_has_tag(conn, POLICY_TAG_WIRED)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_REQUIRE) &&
                (!connection_has_tag(conn, POLICY_TAG_WIFI)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_PROHIBIT) &&
                (connection_has_tag(conn, POLICY_TAG_WIFI)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_REQUIRE) &&
                (!connection_has_tag(conn, POLICY_TAG_CELLULAR)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_PROHIBIT) &&
                (connection_has_tag(conn, POLICY_TAG_CELLULAR)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE) &&
                (!connection_has_tag(conn, POLICY_TAG_TRUSTED)));
        nexthops_disable_if(nexthops, i,
                (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_PROHIBIT) &&
                (connection_has_tag(conn, POLICY_TAG_TRUSTED)));
    });

    if (nexthops_get_curlen(nexthops) == 0)
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
                    (!connection_has_tag(conn, POLICY_TAG_TRUSTED)));
        });

        if ((nexthops_get_curlen(nexthops) == 0) && (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE)) {
            return nexthops;
        }

    } else {
        /* Try to filter out TRUSTED faces */
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    (connection_has_tag(conn, POLICY_TAG_TRUSTED)));
        });
    }

    if (nexthops_get_curlen(nexthops) == 0)
        nexthops->flags = flags;

    /* Other preferences */
    if (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_AVOID) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    connection_has_tag(conn, POLICY_TAG_WIRED));
        });
        if (nexthops_get_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }
    if (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_AVOID) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    connection_has_tag(conn, POLICY_TAG_WIFI));
        });
        if (nexthops_get_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }
    if (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_AVOID) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    connection_has_tag(conn, POLICY_TAG_CELLULAR));
        });
        if (nexthops_get_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }

    if (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_PREFER) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    !connection_has_tag(conn, POLICY_TAG_WIRED));
        });
        if (nexthops_get_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }
    if (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_PREFER) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    !connection_has_tag(conn, POLICY_TAG_WIFI));
        });
        if (nexthops_get_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }
    if (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_PREFER) {
        nexthops_enumerate(nexthops, i, nexthop, {
            conn = connection_table_at(table, nexthop);
            nexthops_disable_if(nexthops, i,
                    !connection_has_tag(conn, POLICY_TAG_CELLULAR));
        });
        if (nexthops_get_curlen(nexthops) == 0)
            nexthops->flags = flags;
    }

    /* Priority */
    uint32_t max_priority = 0;
    nexthops_foreach(nexthops, nexthop, {
        conn = connection_table_at(table, nexthop);
        uint32_t priority = connection_get_priority(conn);
        if (priority > max_priority)
            max_priority = priority;
    });
    nexthops_enumerate(nexthops, i, nexthop, {
        conn = connection_table_at(table, nexthop);
        nexthops_disable_if(nexthops, i,
                connection_get_priority(conn) < max_priority);
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
fib_entry_get_available_nexthops(fib_entry_t * entry, unsigned ingress_id, nexthops_t * new_nexthops)
{
    connection_table_t * table = forwarder_get_connection_table(entry->forwarder);

    /*
     * Give absolute preference to local faces, with no policy, unless
     * ingress_id == ~0, which means we are searching faces on which to
     * advertise our prefix
     */
    if (ingress_id == ~0) {
        /* We create a nexthop structure based on connections */
        // XXX This should be done close to where it is needed
        connection_t * connection;
        connection_table_foreach(table, connection, {
            new_nexthops->elts[nexthops_get_len(new_nexthops)] = connection_table_get_connection_id(table, connection);
            nexthops_inc(new_nexthops);
        });

        return fib_entry_filter_nexthops(entry, new_nexthops, ingress_id, false);
    }

    return fib_entry_filter_nexthops(entry, fib_entry_get_nexthops(entry), ingress_id, true);
}

policy_t
fib_entry_get_policy(const fib_entry_t * entry)
{
    return entry->policy;
}

void
fib_entry_set_policy(fib_entry_t * entry, policy_t policy)
{
    entry->policy = policy;

#ifdef WITH_MAPME
    /*
     * Skip entries that do not correspond to a producer ( / have a locally
     * served prefix / have no local connection as next hop)
     */
    if (!fib_entry_has_local_nexthop(entry))
        return;
    mapme_t * mapme = forwarder_get_mapme(entry->forwarder);
    mapme_send_to_all_nexthops(mapme, entry);
#endif /* WITH_MAPME */
}

#endif /* WITH_POLICY */

void
fib_entry_get_nexthops_add(fib_entry_t * entry, unsigned nexthop)
{
    nexthops_add(fib_entry_get_nexthops(entry), nexthop);
    // XXX TODO
    strategy_vft[entry->strategy.type]->add_nexthop(&entry->strategy, nexthop, NULL);
}

void
fib_entry_get_nexthops_remove(fib_entry_t * entry, unsigned nexthop)
{
    nexthops_remove(fib_entry_get_nexthops(entry), nexthop);
    // XXX TODO
    strategy_vft[entry->strategy.type]->remove_nexthop(&entry->strategy, nexthop, NULL);
}

const nexthops_t *
fib_entry_get_nexthops_get_from_strategy(fib_entry_t * entry,
        const msgbuf_t * msgbuf, bool is_retransmission)
{
    assert(entry);
    assert(msgbuf);

    const prefix_stats_mgr_t * mgr = forwarder_get_prefix_stats_mgr(entry->forwarder);
    assert(mgr);

    /* Filtering */
    nexthops_t new_nexthops = NEXTHOPS_EMPTY;
    nexthops_t * nexthops = fib_entry_get_available_nexthops(entry,
            msgbuf_get_connection_id(msgbuf), &new_nexthops);
    if (nexthops_get_curlen(nexthops) == 0)
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
        prefix_stats_on_retransmission(mgr, &entry->prefix_counters, nexthops);
#endif /* WITH_PREFIX_STATS */

    /*
     * NOTE: We might want to call a forwarding strategy even with no nexthop to
     * take a fallback decision.
     */
    if (nexthops_get_curlen(nexthops) == 0)
        return nexthops;

#ifdef WITH_POLICY
    /*
     * If multipath is disabled, we don't offer much choice to the forwarding
     * strategy, but still go through it for accounting purposes.
     */
    policy_t policy = fib_entry_get_policy(entry);
    if ((policy.tags[POLICY_TAG_MULTIPATH].state == POLICY_STATE_PROHIBIT) ||
            (policy.tags[POLICY_TAG_MULTIPATH].state != POLICY_STATE_AVOID)) {
        nexthops_select_one(nexthops);
    }
#endif /* WITH_POLICY */

    return strategy_vft[entry->strategy.type]->lookup_nexthops(&entry->strategy,
            nexthops, msgbuf);
}

void
fib_entry_on_data(fib_entry_t * entry,
        const nexthops_t * nexthops, const msgbuf_t * msgbuf,
        Ticks pitEntryCreation, Ticks objReception)
{
    assert(entry);
    assert(nexthops);
    assert(msgbuf);

#ifdef WITH_PREFIX_STATS
    const prefix_stats_mgr_t * mgr = forwarder_get_prefix_stats_mgr(entry->forwarder);
    Ticks rtt = objReception - pitEntryCreation;
    prefix_stats_on_data(mgr, &entry->prefix_stats, &entry->prefix_counters,
            nexthops, msgbuf, rtt);
#endif /* WITH_PREFIX_STATS */

    strategy_vft[entry->strategy.type]->on_data(&entry->strategy, nexthops, msgbuf, pitEntryCreation, objReception);
}

void
fib_entry_on_timeout(fib_entry_t * entry, const nexthops_t * nexthops)
{
    assert(entry);
    assert(nexthops);

#ifdef WITH_PREFIX_STATS
    const prefix_stats_mgr_t * mgr = forwarder_get_prefix_stats_mgr(entry->forwarder);
    prefix_stats_on_timeout(mgr, &entry->prefix_counters, nexthops);
#endif /* WITH_PREFIX_STATS */

    strategy_vft[entry->strategy.type]->on_timeout(&entry->strategy, nexthops);
}

Name *
fib_entry_get_prefix(const fib_entry_t * entry)
{
    assert(entry);

    return entry->name;
}


/*
 * Return true if we have at least one local connection as next hop
 */
bool
fib_entry_has_local_nexthop(const fib_entry_t * entry)
{
    connection_table_t * table = forwarder_get_connection_table(entry->forwarder);

    unsigned nexthop;
    nexthops_foreach(fib_entry_get_nexthops(entry), nexthop, {
        const connection_t * conn = connection_table_at(table, nexthop);
        /* Ignore non-local connections */
        if (!connection_is_local(conn))
            continue;
        return true;
    });
    return false;
}

#ifdef WITH_MAPME

void *
fib_entry_get_user_data(const fib_entry_t * entry)
{
    assert(entry);

    return entry->user_data;
}

void
fib_entry_set_user_data(fib_entry_t * entry, const void * user_data,
        void (*user_data_release)(void **))
{
    assert(entry);
    assert(user_data);
    assert(user_data_release);

    entry->user_data = (void *)user_data;
    entry->user_data_release = user_data_release;
}

#endif /* WITH_MAPME */
