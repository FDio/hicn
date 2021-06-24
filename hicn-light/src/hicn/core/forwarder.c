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

/**
 * Event based router
 *
 * This module is the glue around the event scheduler.
 * Its the packet i/o module.
 *
 * Packet processing is done in dispatcher.c, which is the actual wrapper around
 * the event scheduler
 */

#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
//#include <hicn/hicn-light/config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "connection_table.h"
#include "content_store.h"
#include "fib.h"
#include "forwarder.h"
#include "listener_table.h"
#ifdef WITH_MAPME
#include "mapme.h"
#endif /* WITH_MAPME */
#include "msgbuf.h"
#include "msgbuf_pool.h"
#include "pit.h"
#include "../config/configuration.h"
#include "../config/configuration_file.h"
#include "../io/base.h" // MAX_MSG

#ifdef WITH_PREFIX_STATS
#include <hicn/core/prefix_stats.h>
#endif /* WITH_PREFIX_STATS */

#include <hicn/core/wldr.h>
#include <hicn/util/log.h>

typedef struct {
    uint32_t countReceived; // Interest & Data only
    uint32_t countInterestsReceived;
    uint32_t countObjectsReceived;

    uint32_t countInterestsAggregated;

    uint32_t countDropped;
    uint32_t countInterestsDropped;
    uint32_t countDroppedNoRoute;
    uint32_t countDroppedNoReversePath;

    uint32_t countDroppedConnectionNotFound;
    uint32_t countObjectsDropped;
    uint32_t countOtherDropped;

    uint32_t countSendFailures;
    uint32_t countInterestForwarded;
    uint32_t countObjectsForwarded;
    uint32_t countInterestsSatisfiedFromStore;

    uint32_t countDroppedNoHopLimit;
    uint32_t countDroppedZeroHopLimitFromRemote;
    uint32_t countDroppedZeroHopLimitToRemote;
} forwarder_stats_t;

struct forwarder_s {
//    uint16_t server_port;

// XXX TODO signal handling
#if 0
    PARCEventSignal *signal_int;
    PARCEventSignal *signal_term;
#ifndef _WIN32
    PARCEventSignal *signal_usr1;
#endif
#endif

    // used by seed48 and nrand48
    unsigned short seed[3];

    connection_table_t * connection_table;
    listener_table_t * listener_table;
    configuration_t *config;


    pit_t * pit;
    cs_t * cs;
    fib_t * fib;
    msgbuf_pool_t * msgbuf_pool;

#ifdef WITH_MAPME
    mapme_t * mapme;
#endif /* WITH_MAPME */

    bool store_in_cs;
    bool serve_from_cs;

    forwarder_stats_t stats;
#ifdef WITH_PREFIX_STATS
    prefix_stats_mgr_t prefix_stats_mgr;
#endif /* WITH_PREFIX_STATS */

    /*
     * The message forwarder has to decide whether to queue incoming packets for
     * batching, or trigger the transmission on the connection
     */
    unsigned pending_conn[MAX_MSG];
    size_t num_pending_conn;

    //msgbuf_t msgbuf; /* Storage for msgbuf, which are currently processed 1 by 1 */

};

#if 0
// signal traps through the event scheduler
static void _signal_cb(int, PARCEventType, void *);
#endif

/**
 * Reseed our pseudo-random number generator.
 */
static
void
forwarder_seed(forwarder_t * forwarder) {
#ifndef _WIN32
    int fd;
    ssize_t res;

    res = -1;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        res = read(fd, forwarder->seed, sizeof(forwarder->seed));
        close(fd);
    }
    if (res != sizeof(forwarder->seed)) {
        forwarder->seed[1] = (unsigned short)getpid(); /* better than no entropy */
        forwarder->seed[2] = (unsigned short)time(NULL);
    }
    /*
     * The call to seed48 is needed by cygwin, and should be harmless
     * on other platforms.
     */
    seed48(forwarder->seed);
#else
    forwarder->seed[1] = (unsigned short)getpid(); /* better than no entropy */
    forwarder->seed[2] = (unsigned short)time(NULL);
#endif
}

forwarder_t *
forwarder_create()
{
    forwarder_t * forwarder = malloc(sizeof(forwarder_t));
    if (!forwarder)
        goto ERR_MALLOC;

    forwarder_seed(forwarder);

    forwarder->config = configuration_create(forwarder);
    if (!forwarder->config)
        goto ERR_CONFIG;

    forwarder->listener_table = listener_table_create();
    if (!forwarder->listener_table)
        goto ERR_LISTENER_TABLE;

    forwarder->connection_table = connection_table_create();
    if (!forwarder->connection_table)
        goto ERR_CONNECTION_TABLE;

    forwarder->fib = fib_create(forwarder);
    if (!forwarder->fib)
        goto ERR_FIB;

    forwarder->msgbuf_pool = msgbuf_pool_create();
    if (!forwarder->msgbuf_pool)
        goto ERR_PACKET_POOL;

    forwarder->pit = pit_create();
    if (!forwarder->pit)
        goto ERR_PIT;

    size_t objectStoreSize =
        configuration_cs_get_size(forwarder_get_configuration(forwarder));
    forwarder->cs = _cs_create(CS_TYPE_LRU,
            objectStoreSize, 0);
    if (!forwarder->cs)
        goto ERR_CS;

    // the two flags for the cs are set to true by default. If the cs
    // is active it always work as expected unless the use modifies this
    // values using controller
    forwarder->store_in_cs = true;
    forwarder->serve_from_cs = true;

#if 0
    forwarder->signal_term = dispatcher_CreateSignalEvent(
            forwarder->dispatcher, _signal_cb, forwarder, SIGTERM);
    dispatcher_StartSignalEvent(forwarder->dispatcher, forwarder->signal_term);

    forwarder->signal_int = dispatcher_CreateSignalEvent(
            forwarder->dispatcher, _signal_cb, forwarder, SIGINT);
    dispatcher_StartSignalEvent(forwarder->dispatcher, forwarder->signal_int);
#ifndef _WIN32
    forwarder->signal_usr1 = dispatcher_CreateSignalEvent(
            forwarder->dispatcher, _signal_cb, forwarder, SIGPIPE);
    dispatcher_StartSignalEvent(forwarder->dispatcher, forwarder->signal_usr1);
#endif
#endif

#ifdef WITH_MAPME
    forwarder->mapme = mapme_create(forwarder);
    if (!forwarder->mapme)
        goto ERR_MAPME;
#endif /* WITH_MAPME */


    /* ignore child */
#ifndef _WIN32
    signal(SIGCHLD, SIG_IGN);

    /* ignore tty signals */
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
#endif

#ifdef WITH_PREFIX_STATS
    if (prefix_stats_mgr_initialize(&forwarder->prefix_stats_mgr, forwarder) < 0)
        goto ERR_MGR;
#endif /* WITH_PREFIX_STATS */

    return forwarder;

ERR_MGR:
#ifdef WITH_MAPME
ERR_MAPME:
#endif /* WITH_MAPME */

#if 0
    dispatcher_DestroySignalEvent(forwarder->dispatcher,
            &(forwarder->signal_int));
    dispatcher_DestroySignalEvent(forwarder->dispatcher,
            &(forwarder->signal_term));
#ifndef _WIN32
    dispatcher_DestroySignalEvent(forwarder->dispatcher,
            &(forwarder->signal_usr1));
#endif

    // do the dispatcher last
    dispatcher_Destroy(&(forwarder->dispatcher));
#endif

    cs_free(forwarder->cs);
ERR_CS:
    pit_free(forwarder->pit);
ERR_PIT:
    msgbuf_pool_free(forwarder->msgbuf_pool);
ERR_PACKET_POOL:
    fib_free(forwarder->fib);
ERR_FIB:
    connection_table_free(forwarder->connection_table);
ERR_CONNECTION_TABLE:
    listener_table_free(forwarder->listener_table);
ERR_LISTENER_TABLE:
    configuration_free(forwarder->config);
ERR_CONFIG:
    free(forwarder);
ERR_MALLOC:
    return NULL;
}

void
forwarder_free(forwarder_t * forwarder)
{
    assert(forwarder);

    prefix_stats_mgr_finalize(&forwarder->prefix_stats_mgr);

#ifdef WITH_MAPME
    mapme_free(forwarder->mapme);
#endif /* WITH_MAPME */

#if 0
    dispatcher_DestroySignalEvent(forwarder->dispatcher,
            &(forwarder->signal_int));
    dispatcher_DestroySignalEvent(forwarder->dispatcher,
            &(forwarder->signal_term));
#ifndef _WIN32
    dispatcher_DestroySignalEvent(forwarder->dispatcher,
            &(forwarder->signal_usr1));
#endif

    // do the dispatcher last
    dispatcher_Destroy(&(forwarder->dispatcher));
#endif

    cs_free(forwarder->cs);
    pit_free(forwarder->pit);
    msgbuf_pool_free(forwarder->msgbuf_pool);
    fib_free(forwarder->fib);
    connection_table_free(forwarder->connection_table);
    listener_table_free(forwarder->listener_table);
    configuration_free(forwarder->config);
    free(forwarder);
}

void
forwarder_setup_all_listeners(forwarder_t * forwarder, uint16_t port,
        const char * local_path)
{
    assert(forwarder);
    assert(local_path);

    listener_setup_all(forwarder, port, local_path);
}

void
forwarder_setup_local_listeners(forwarder_t * forwarder, uint16_t port)
{
    assert(forwarder);
    listener_setup_local_ipv4(forwarder, port);
}

void
forwarder_read_config(forwarder_t * forwarder, const char * filename)
{
    configuration_file_t *cfg = configuration_file_create(forwarder, filename);
    if (!cfg)
        return;

    configuration_file_process(cfg);
    configuration_file_free(cfg);
}

configuration_t *
forwarder_get_configuration(forwarder_t * forwarder)
{
    assert(forwarder);
    return forwarder->config;
}

connection_table_t *
forwarder_get_connection_table(const forwarder_t * forwarder)
{
    assert(forwarder);
    return forwarder->connection_table;
}

listener_table_t *
forwarder_get_listener_table(forwarder_t * forwarder)
{
    assert(forwarder);
    return forwarder->listener_table;
}

void
forwarder_cs_set_store(forwarder_t * forwarder, bool val)
{
    assert(forwarder);
    forwarder->store_in_cs = val;
}

bool
forwarder_cs_get_store(forwarder_t * forwarder)
{
    assert(forwarder);
    return forwarder->store_in_cs;
}

void
forwarder_cs_set_serve(forwarder_t * forwarder, bool val)
{
    assert(forwarder);
    forwarder->serve_from_cs = val;
}

bool
forwarder_cs_get_serve(forwarder_t * forwarder)
{
    assert(forwarder);
    return forwarder->serve_from_cs;
}

void
forwarder_cs_set_size(forwarder_t * forwarder, size_t size)
{
    assert(forwarder);

    cs_free(forwarder->cs);

    // XXX TODO
#if 0
    ContentStoreConfig csConfig = {.objectCapacity =
        maximumContentStoreSize};

    forwarder->cs =
        csLRU_Create(&csConfig, forwarder->logger);
#endif
}

void
forwarder_cs_clear(forwarder_t * forwarder)
{
    assert(forwarder);

    cs_clear(forwarder->cs);
}

/**
 * @function forwarder_Drop
 * @abstract Whenever we "drop" a message, increment countes
 * @discussion
 *   This is a bookkeeping function.  It increments the appropriate counters.
 *
 *   The default action for a message is to destroy it in
 * <code>forwarder_Receive()</code>, so this function does not need to do
 * that.
 *
 */
static
ssize_t
forwarder_drop(forwarder_t * forwarder, off_t msgbuf_id)
{
    forwarder->stats.countDropped++;

    const msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    switch (msgbuf_get_type(msgbuf)) {
        case MSGBUF_TYPE_INTEREST:
            forwarder->stats.countInterestsDropped++;
            break;

        case MSGBUF_TYPE_DATA:
            forwarder->stats.countObjectsDropped++;
            break;

        default:
            forwarder->stats.countOtherDropped++;
            break;
    }

    return msgbuf_get_len(msgbuf);
    // dont destroy message here, its done at end of receive
}

/*
 *   If the hoplimit is equal to 0, then we may only forward it to local
 * applications.  Otherwise, we may forward it off the system.
 *
 */
static
ssize_t
forwarder_forward_via_connection(forwarder_t * forwarder, off_t msgbuf_id,
        unsigned conn_id)
{
    connection_table_t * table = forwarder_get_connection_table(forwarder);

    const msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    const connection_t * conn = connection_table_get_by_id(table, conn_id);

    if (!conn) {
        forwarder->stats.countDroppedConnectionNotFound++;
        DEBUG("forward msgbuf %lu to interface %u not found (count %u)",
                msgbuf_id, conn_id, forwarder->stats.countDroppedConnectionNotFound);
        return forwarder_drop(forwarder, msgbuf_id);
    }

    /* Always queue the packet... */
    bool success = connection_send(conn, msgbuf_id, true);

    /* ... and mark the connection as pending if this is not yet the case */
    unsigned i;
    for (i = 0; i < forwarder->num_pending_conn; i++) {
        if (forwarder->pending_conn[i] == conn_id)
            break;
    }
    if (i == forwarder->num_pending_conn)
        forwarder->pending_conn[forwarder->num_pending_conn++] = conn_id;

    if (!success) {
        forwarder->stats.countSendFailures++;

        DEBUG("forward msgbuf %llu to interface %u send failure (count %u)",
                msgbuf_id, conn_id, forwarder->stats.countSendFailures);
        return forwarder_drop(forwarder, msgbuf_id);
    }

    switch (msgbuf_get_type(msgbuf)) {
        case MSGBUF_TYPE_INTEREST:
            forwarder->stats.countInterestForwarded++;
            break;

        case MSGBUF_TYPE_DATA:
            forwarder->stats.countObjectsForwarded++;
            break;

        default:
            break;
    }

    DEBUG("forward msgbuf %p to interface %u (int %u, obj %u)", msgbuf,
            conn_id, forwarder->stats.countInterestForwarded,
            forwarder->stats.countObjectsForwarded);

    return (msgbuf_get_len(msgbuf));
}

/**
 * @function forwarder_forward_to_nexthops
 * @abstract Try to forward to each nexthop listed in the NumberSet
 * @discussion
 *   Will not forward to the ingress connection.
 *
 * @return The number of nexthops tried
 */
static
unsigned
forwarder_forward_to_nexthops(forwarder_t * forwarder,
        off_t msgbuf_id, const nexthops_t * nexthops)
{
    unsigned forwardedCopies = 0;

    const msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
    msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
    unsigned ingressId = msgbuf_get_connection_id(msgbuf);
    uint32_t old_path_label = 0;

    if (msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA)
        old_path_label = msgbuf_get_pathlabel(msgbuf);

    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
        if (nexthop == ingressId)
            continue;

        forwardedCopies++;
        forwarder_forward_via_connection(forwarder, msgbuf_id, nexthop);

        // everytime we send out a message we need to restore the original path
        // label of the message this is important because we keep a single copy
        // of the message (single pointer) and we modify the path label at each
        // send.
        if (msgbuf_get_type(msgbuf) == MSGBUF_TYPE_DATA)
            msgbuf_set_pathlabel(msgbuf, old_path_label);
    });

    return forwardedCopies;
}


static
bool
forwarder_forward_via_fib(forwarder_t * forwarder, off_t msgbuf_id,
        pit_verdict_t verdict)
{
    assert(forwarder);
    assert(msgbuf_id_is_valid(msgbuf_id));

    const msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
    msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);
    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

    fib_entry_t *fib_entry = fib_match_message(forwarder->fib, msgbuf);
    if (!fib_entry)
        return false;

    // XXX TODO PROBE HOOK MIGHT BE HANDLED ELSEWHERE
    if (msgbuf_is_probe(msgbuf)) {
        connection_table_t * table = forwarder_get_connection_table(forwarder);
        const nexthops_t * nexthops = fib_entry_get_nexthops(fib_entry);

        unsigned nexthop;
        nexthops_foreach(nexthops, nexthop, {
            connection_t * conn = connection_table_at(table, nexthop);
            if (!conn)
                continue;
            if (!connection_is_local(conn))
                continue;
            uint8_t * packet = msgbuf_get_packet(msgbuf);
            unsigned size = msgbuf_get_len(msgbuf);
            connection_t *  reply_connection = connection_table_get_by_id(table,
                    msgbuf_get_connection_id(msgbuf));
            if (messageHandler_IsInterest(packet)) {
                messageHandler_CreateProbeReply(packet, HF_INET6_TCP);
                connection_send_packet(reply_connection, packet, size);
            }
            return false;
        });
    }

    pit_entry_t * entry = pit_lookup(forwarder->pit, msgbuf);
    if (!entry)
        return false;

    pit_entry_set_fib_entry(entry, fib_entry);

    const nexthops_t * nexthops = fib_entry_get_nexthops_from_strategy(fib_entry,
            msgbuf, verdict);

    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
        pit_entry_egress_add(entry, nexthop);
    });

    // this requires some additional checks. It may happen that some of the output
    // faces selected by the forwarding strategy are not usable. So far all the
    // forwarding strategy return only valid faces (or an empty list)

#if 0
    // The function GetPitEntry encreases the ref counter in the pit entry
    // we need to decrease it
    entry_Release(&entry);
#endif

    if (forwarder_forward_to_nexthops(forwarder, msgbuf_id, nexthops) <= 0) {
        DEBUG("Message %p returned an emtpy next hop set", msgbuf);
        return false;
    }
    return true;

}


static
bool
_satisfy_from_cs(forwarder_t * forwarder, off_t msgbuf_id)
{
    assert(forwarder);
    assert(msgbuf_id_is_valid(msgbuf_id));

    msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

    if (msgbuf_get_lifetime(msgbuf) == 0)
        return false;

    if (!forwarder->serve_from_cs)
        return false;

    // See if there's a match in the store.
    off_t data_msgbuf_id = cs_match(forwarder_get_cs(forwarder), msgbuf_pool, msgbuf_id,
            ticks_now());

    if (msgbuf_id_is_valid(data_msgbuf_id))
        return false;

    // Remove it from the PIT.  nexthops is allocated, so need to destroy
    nexthops_t * nexthops = pit_on_data(forwarder->pit, msgbuf_pool, data_msgbuf_id);
    assert(nexthops); // Illegal state: got a null nexthops for an interest we just inserted

    // send message in reply, then done
    forwarder->stats.countInterestsSatisfiedFromStore++;

    DEBUG("Message %lu satisfied from content store (satisfied count %u)",
            msgbuf_id, forwarder->stats.countInterestsSatisfiedFromStore);

    msgbuf_t * data_msgbuf = msgbuf_pool_at(msgbuf_pool, data_msgbuf_id);
    msgbuf_reset_pathlabel(data_msgbuf);

    forwarder_forward_to_nexthops(forwarder, data_msgbuf_id, nexthops);

    return true;
}

/**
 * @function forwarder_process_interest
 * @abstract Receive an interest from the network
 * @discussion
 *   (1) if interest in the PIT, aggregate in PIT
 *   (2) if interest in the ContentStore, reply
 *   (3) if in the FIB, forward
 *   (4) drop
 *
 */
static
ssize_t
forwarder_process_interest(forwarder_t * forwarder, off_t msgbuf_id)
{
    assert(forwarder);
    assert(msgbuf_id_is_valid(msgbuf_id));

    msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    assert(msgbuf_get_type(msgbuf) == MSGBUF_TYPE_INTEREST);

    forwarder->stats.countReceived++;
    forwarder->stats.countInterestsReceived++;

    char *nameString = name_ToString(msgbuf_get_name(msgbuf));
    DEBUG( "Message %p ingress %3u length %5u received name %s", msgbuf,
            msgbuf_get_connection_id(msgbuf), msgbuf_get_len(msgbuf), nameString);
    free(nameString);


    // (1) Try to aggregate in PIT
    pit_verdict_t verdict = pit_on_interest(forwarder->pit, msgbuf_pool, msgbuf_id);
    switch(verdict) {
        case PIT_VERDICT_AGGREGATE:
            forwarder->stats.countInterestsAggregated++;
            DEBUG("Message %p aggregated in PIT (aggregated count %u)",
                    msgbuf, forwarder->stats.countInterestsAggregated);
            return msgbuf_get_len(msgbuf);

        case PIT_VERDICT_FORWARD:
        case PIT_VERDICT_RETRANSMIT:
            DEBUG("Message %p not aggregated in PIT (aggregated count %u)",
                    msgbuf, forwarder->stats.countInterestsAggregated);
            break;
    }

    // At this point, we just created a PIT entry.  If we don't forward the
    // interest, we need to remove the PIT entry.

    // (2) Try to satisfy from content store
    if (_satisfy_from_cs(forwarder, msgbuf_id)) {
        // done
        // If we found a content object in the CS,
        // messageProcess_Satisfy_from_cs already cleared the PIT state
        return msgbuf_get_len(msgbuf);
    }

    // (3) Try to forward it
    if (forwarder_forward_via_fib(forwarder, msgbuf_id, verdict)) {
        // done
        return msgbuf_get_len(msgbuf);
    }

    // Remove the PIT entry?
    forwarder->stats.countDroppedNoRoute++;

    DEBUG("Message %lu did not match FIB, no route (count %u)",
                msgbuf_id, forwarder->stats.countDroppedNoRoute);

    return forwarder_drop(forwarder, msgbuf_id);
}

/**
 * @function forwarder_process_data
 * @abstract Process an in-bound content object
 * @discussion
 *   (1) If it does not match anything in the PIT, drop it
 *   (2) Add to Content Store
 *   (3) Reverse path forward via PIT entries
 *
 * @param <#param1#>
 */
static
ssize_t
forwarder_process_data(forwarder_t * forwarder, off_t msgbuf_id)
{
    msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
    const msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    char *nameString = name_ToString(msgbuf_get_name(msgbuf));
    DEBUG( "Message %lu ingress %3u length %5u received name %s", msgbuf_id,
            msgbuf_get_connection_id(msgbuf), msgbuf_get_len(msgbuf), nameString);
    free(nameString);

    forwarder->stats.countReceived++;
    forwarder->stats.countObjectsReceived++;

    nexthops_t * ingressSetUnion = pit_on_data(forwarder->pit, msgbuf_pool, msgbuf_id);
    if (!ingressSetUnion) {
        // (1) If it does not match anything in the PIT, drop it
        forwarder->stats.countDroppedNoReversePath++;

        DEBUG("Message %lu did not match PIT, no reverse path (count %u)",
                msgbuf_id, forwarder->stats.countDroppedNoReversePath);

        // MOVE PROBE HOOK ELSEWHERE
        // XXX relationship with forwarding strategy... insert hooks
        // if the packet is a probe we need to analyze it
        // NOTE : probes are not stored in PIT
        if (msgbuf_is_probe(msgbuf)) {
            fib_entry_t *entry = fib_match_message(forwarder->fib, msgbuf);
            if (entry && fib_entry_strategy_type(entry) == STRATEGY_TYPE_LOW_LATENCY) {
                nexthops_t probe_nexthops;
                nexthops_add(&probe_nexthops, msgbuf_get_connection_id(msgbuf));
                fib_entry_on_data(entry, &probe_nexthops, msgbuf, 0, ticks_now());

                // XXX TODO CONFIRM WE DON'T EXIT HERE ?
            }
        }

        // we store the packets in the content store enven in the case where there
        // is no match in the PIT table in this way the applications can push the
        // content in the CS of the forwarder. We allow this only for local faces
        const connection_table_t * table = forwarder_get_connection_table(forwarder);
        const connection_t *  conn = connection_table_get_by_id(table, msgbuf_get_connection_id(msgbuf));

        if (forwarder->store_in_cs && connection_is_local(conn)) {
            cs_add(forwarder->cs, msgbuf_pool, msgbuf_id, ticks_now());
            DEBUG("Message %p store in CS anyway", msgbuf);
        }

        return forwarder_drop(forwarder, msgbuf_id);
    } else {
        // (2) Add to Content Store. Store may remove expired content, if necessary,
        // depending on store policy.
        if (forwarder->store_in_cs) {
            cs_add(forwarder->cs, msgbuf_pool, msgbuf_id, ticks_now());
        }
        // (3) Reverse path forward via PIT entries
        return forwarder_forward_to_nexthops(forwarder, msgbuf_id, ingressSetUnion);

    }
}

void
forwarder_flush_connections(forwarder_t * forwarder)
{
    const connection_table_t * table = forwarder_get_connection_table(forwarder);

    for (unsigned i = 0; i < forwarder->num_pending_conn; i++) {
        unsigned conn_id = forwarder->pending_conn[i];
        const connection_t *  conn = connection_table_at(table, conn_id);
        if (!connection_flush(conn)) {
            WARN("Could not flush connection queue");
            // XXX keep track of non flushed connections...
        }
    }
    forwarder->num_pending_conn = 0;
}

// XXX move to wldr file, worst case in connection.
void
forwarder_apply_wldr(const forwarder_t * forwarder, const msgbuf_t * msgbuf, connection_t * connection)
{
    // this are the checks needed to implement WLDR. We set wldr only on the STAs
    // and we let the AP to react according to choice of the client.
    // if the STA enables wldr using the set command, the AP enable wldr as well
    // otherwise, if the STA disable it the AP remove wldr
    // WLDR should be enabled only on the STAs using the command line
    // TODO
    // disable WLDR command line on the AP
    if (msgbuf_has_wldr(msgbuf)) {
        if (connection_has_wldr(connection)) {
            // case 1: WLDR is enabled
            connection_wldr_detect_losses(connection, msgbuf);
        } else if (!connection_has_wldr(connection) &&
                connection_wldr_autostart_is_allowed(connection)) {
            // case 2: We are on an AP. We enable WLDR
            connection_wldr_enable(connection, true);
            connection_wldr_detect_losses(connection, msgbuf);
        }
        // case 3: Ignore WLDR
    } else {
        if (connection_has_wldr(connection) && connection_wldr_autostart_is_allowed(connection)) {
            // case 1: STA do not use WLDR, we disable it
            connection_wldr_enable(connection, false);
        }
    }
}

bool
forwarder_add_or_update_route(forwarder_t * forwarder, ip_prefix_t * prefix,
        unsigned ingress_id)
{
    assert(forwarder);
    assert(prefix);

    configuration_t *config = forwarder_get_configuration(forwarder);

    char prefix_s[MAXSZ_IP_PREFIX];
    int rc = ip_prefix_snprintf(prefix_s, MAXSZ_IP_PREFIX, prefix);
    assert(rc < MAXSZ_IP_PREFIX);
    if (rc < 0)
        return false;

    // XXX TODO this should store options too
    strategy_type_t strategy_type = configuration_get_strategy(config, prefix_s);

    Name * name_prefix = name_CreateFromAddress(prefix->family,
            prefix->address, prefix->len);
    // XXX TODO error handling
    fib_entry_t * entry = fib_contains(forwarder->fib, name_prefix);
    if (!entry) {
        entry = fib_entry_create(name_prefix, strategy_type, NULL, forwarder);
        fib_entry_nexthops_add(entry, ingress_id);
        fib_add(forwarder->fib, entry);
    } else {
        fib_entry_nexthops_add(entry, ingress_id);
    }

    name_Release(&name_prefix);

    return true;
}


bool
forwarder_remove_route(forwarder_t * forwarder, ip_prefix_t * prefix,
        unsigned ingress_id)
{
    assert(forwarder);
    assert(prefix);

    Name *name_prefix = name_CreateFromAddress(prefix->family,
            prefix->address, prefix->len);
    // XXX TODO error handling
    fib_remove(forwarder->fib, name_prefix, ingress_id);
    name_Release(&name_prefix);

    return true;
}

#ifdef WITH_POLICY

bool
forwarder_add_or_update_policy(forwarder_t * forwarder, ip_prefix_t * prefix,
        hicn_policy_t * policy)
{
    assert(forwarder);
    assert(prefix);
    assert(policy);

    Name *name_prefix = name_CreateFromAddress(prefix->family, prefix->address,
            prefix->len);
    // XXX TODO error handling
    fib_entry_t *entry = fib_contains(forwarder->fib, name_prefix);
    if (!entry)
        return false;
    fib_entry_set_policy(entry, *policy);

    name_Release(&name_prefix);

    return true;
}

bool
forwarder_remove_policy(forwarder_t * forwarder, ip_prefix_t * prefix)
{
    assert(forwarder);
    assert(prefix);

    Name *name_prefix = name_CreateFromAddress(prefix->family, prefix->address,
            prefix->len);
    // XXX TODO error handling
    fib_entry_t * entry = fib_contains(forwarder->fib, name_prefix);
    name_Release(&name_prefix);

    if (!entry)
        return false;

    fib_entry_set_policy(entry, POLICY_NONE);

    return true;
}

#endif /* WITH_POLICY */

void
forwarder_remove_connection_id_from_routes(forwarder_t * forwarder,
        unsigned connection_id)
{
    assert(forwarder);

    fib_remove_connection_id(forwarder->fib, connection_id);
}

void
forwarder_set_strategy(forwarder_t * forwarder, Name * name_prefix,
        strategy_type_t strategy_type, strategy_options_t * strategy_options)
{
    assert(forwarder);
    assert(name_prefix);
    assert(STRATEGY_TYPE_VALID(strategy_type));
    /* strategy_options might be NULL */

    fib_entry_t * entry = fib_contains(forwarder->fib, name_prefix);
    if (!entry)
        return;

    fib_entry_set_strategy(entry, strategy_type, strategy_options);
}

cs_t *
forwarder_get_cs(const forwarder_t * forwarder)
{
    assert(forwarder);

    return forwarder->cs;
}

// =======================================================

#if 0
static void _signal_cb(int sig, PARCEventType events, void *user_data) {
    forwarder_t * forwarder = (forwarder_t *)user_data;

    WARN("signal %d events %d", sig, events);

    switch ((int)sig) {
        case SIGTERM:
            WARN("Caught an terminate signal; exiting cleanly.");
            dispatcher_Stop(forwarder->dispatcher);
            break;

        case SIGINT:
            WARN("Caught an interrupt signal; exiting cleanly.");
            dispatcher_Stop(forwarder->dispatcher);
            break;
#ifndef _WIN32
        case SIGUSR1:
            // dump stats
            break;
#endif

        default:
            break;
    }
}
#endif

fib_t *
forwarder_get_fib(forwarder_t * forwarder)
{
    return forwarder->fib;
}

msgbuf_pool_t *
forwarder_get_msgbuf_pool(const forwarder_t * forwarder)
{
    return forwarder->msgbuf_pool;
}

#ifdef WITH_MAPME
void
forwarder_on_connection_event(const forwarder_t * forwarder,
        const connection_t * connection, connection_event_t event)
{
    mapme_on_connection_event(forwarder->mapme, connection, event);
}

mapme_t *
forwarder_get_mapme(const forwarder_t * forwarder) {
    return forwarder->mapme;
}

#endif /* WITH_MAPME */

#ifdef WITH_PREFIX_STATS
const prefix_stats_mgr_t *
forwarder_get_prefix_stats_mgr(const forwarder_t * forwarder)
{
    return &forwarder->prefix_stats_mgr;
}
#endif /* WITH_PREFIX_STATS */

/**
 * @brief Process a packet by creating the corresponding message buffer and
 * dispatching it to the forwarder for further processing.
 * @param[in] forwarder Forwarder instance.
 *
 */
// XXX ??? XXX = process for listener as we are resolving connection id
//

msgbuf_type_t get_type_from_packet(uint8_t * packet)
{
    if (messageHandler_IsTCP(packet)) {
        if (messageHandler_IsData(packet)) {
            return MSGBUF_TYPE_DATA;
        } else if (messageHandler_IsInterest(packet)) {
            return MSGBUF_TYPE_INTEREST;
        } else {
            return MSGBUF_TYPE_UNDEFINED;
        }

    } else if (messageHandler_IsWldrNotification(packet)) {
        return MSGBUF_TYPE_WLDR_NOTIFICATION;

    } else if (mapme_match_packet(packet)) {
        return MSGBUF_TYPE_MAPME;

    } else if (*packet == REQUEST_LIGHT) {
        return MSGBUF_TYPE_COMMAND;

    } else {
        return MSGBUF_TYPE_UNDEFINED;
    }
}

ssize_t
forwarder_receive(forwarder_t * forwarder, listener_t * listener,
        off_t msgbuf_id, address_pair_t * pair, Ticks now)
{
    assert(forwarder);
    /* listener can be NULL */
    assert(msgbuf_id_is_valid(msgbuf_id));
    assert(pair);

    msgbuf_pool_t * msgbuf_pool = forwarder_get_msgbuf_pool(forwarder);
    msgbuf_t * msgbuf = msgbuf_pool_at(msgbuf_pool, msgbuf_id);

    assert(msgbuf);

    uint8_t * packet = msgbuf_get_packet(msgbuf);
    size_t size = msgbuf_get_len(msgbuf);

    // TODO: the assert fails
    // size_t tmp = messageHandler_GetTotalPacketLength(packet);
    // (void) tmp;
    // assert(messageHandler_GetTotalPacketLength(packet) == size); // XXX confirm ?

    /* Connection lookup */
    const connection_table_t * table = forwarder_get_connection_table(listener->forwarder);
    connection_t * connection = connection_table_get_by_pair(table, pair);
    unsigned conn_id = connection
        ? connection_table_get_connection_id(table, connection)
        : CONNECTION_ID_UNDEFINED;

    assert((conn_id != CONNECTION_ID_UNDEFINED) || listener);

    msgbuf_type_t type = get_type_from_packet(msgbuf_get_packet(msgbuf));

    msgbuf->type = type;
    msgbuf->connection_id = conn_id;
    msgbuf->recv_ts = now;
    msgbuf->refs = 1;

    switch(type) {
        case MSGBUF_TYPE_INTEREST:
            if (!connection_id_is_valid(msgbuf->connection_id))
                msgbuf->connection_id = listener_create_connection(listener, pair);
            msgbuf->id.name = name_create_from_interest(packet);
            forwarder_apply_wldr(forwarder, msgbuf, connection);
            forwarder_process_interest(forwarder, msgbuf_id);
            break;

        case MSGBUF_TYPE_DATA:
            if (!connection_id_is_valid(msgbuf->connection_id))
                return forwarder_drop(forwarder, msgbuf_id);
            msgbuf->id.name = name_create_from_data(packet);
            forwarder_apply_wldr(forwarder, msgbuf, connection);
            forwarder_process_data(forwarder, msgbuf_id);
            break;

        case MSGBUF_TYPE_WLDR_NOTIFICATION:
            if (!connection_id_is_valid(msgbuf->connection_id))
                return forwarder_drop(forwarder, msgbuf_id);
            connection_wldr_handle_notification(connection, msgbuf);
            return msgbuf_get_len(msgbuf);

        case MSGBUF_TYPE_MAPME:
            // XXX what about acks ?
            if (!connection_id_is_valid(msgbuf->connection_id))
                msgbuf->connection_id = listener_create_connection(listener, pair);
            mapme_process(forwarder->mapme, msgbuf);
            return msgbuf_get_len(msgbuf);

        case MSGBUF_TYPE_COMMAND:
            // Create the connection to send the ack back
            if (!connection_id_is_valid(msgbuf->connection_id))
                msgbuf->connection_id = listener_create_connection(listener, pair);

            msg_header_t * msg = (msg_header_t*) packet;
            msgbuf->command.type = msg->header.command_id;
            if (msgbuf->command.type >= COMMAND_TYPE_N || msgbuf->command.type == COMMAND_TYPE_UNDEFINED) {
                ERROR("Invalid command");
                return -msgbuf_get_len(msgbuf);
            }
            return configuration_receive_command(forwarder->config, msgbuf);

        case MSGBUF_TYPE_UNDEFINED:
        case MSGBUF_TYPE_N:
            // XXX Unexpected... shall we abort ?
            return forwarder_drop(forwarder, msgbuf_id);
    }

    return size;
}
