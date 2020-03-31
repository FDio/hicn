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
#include <hicn/hicn-light/config.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <hicn/base/connection_table.h>
#include <hicn/base/listener_table.h>
#include <hicn/base/pit.h>
#include <hicn/core/fib.h>
#include <hicn/base/content_store.h>
#include <hicn/core/forwarder.h>
#include <hicn/core/messagePacketType.h>
#ifdef WITH_MAPME
#include <hicn/core/mapme.h>
#endif /* WITH_MAPME */
#include <hicn/config/configuration.h>
#include <hicn/config/configuration_file.h>

#ifdef WITH_PREFIX_STATS
#include <hicn/base/prefix_stats.h>
#endif /* WITH_PREFIX_STATS */

#include <hicn/core/wldr.h>
#include <hicn/util/log.h>

#define DEFAULT_PIT_SIZE 65535

typedef struct {
    uint32_t countReceived;
    uint32_t countInterestsReceived;
    uint32_t countObjectsReceived;

    uint32_t countInterestsAggregated;

    uint32_t countDropped;
    uint32_t countInterestsDropped;
    uint32_t countDroppedNoRoute;
    uint32_t countDroppedNoReversePath;

    uint32_t countDroppedConnectionNotFound;
    uint32_t countObjectsDropped;

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
    Configuration *config;


    pit_t * pit;
    content_store_t * content_store;
    fib_t * fib;

#ifdef WITH_MAPME
    mapme_t * mapme;
#endif /* WITH_MAPME */

    bool store_in_content_store;
    bool serve_from_content_store;

    forwarder_stats_t stats;
#ifdef WITH_PREFIX_STATS
    prefix_stats_mgr_t prefix_stats_mgr;
#endif /* WITH_PREFIX_STATS */

    /*
     * The message forwarder has to decide whether to queue incoming packets for
     * batching, or trigger the transmission on the connection
     */
    unsigned pending_batch;
    unsigned pending_conn[MAX_MSG];
    size_t num_pending_conn;

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

    forwarder->pit = pit_create(DEFAULT_PIT_SIZE);
    if (!forwarder->pit)
        goto ERR_PIT;

    size_t objectStoreSize =
        configuration_content_store_get_size(forwarder_get_configuration(forwarder));
    forwarder->content_store = content_store_create(CONTENT_STORE_TYPE_LRU,
            objectStoreSize);
    if (!forwarder->content_store)
        goto ERR_CONTENT_STORE;

    // the two flags for the content_store are set to true by default. If the content_store
    // is active it always work as expected unless the use modifies this
    // values using controller
    forwarder->store_in_content_store = true;
    forwarder->serve_from_content_store = true;

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

    content_store_free(forwarder->content_store);
ERR_CONTENT_STORE:
    pit_free(forwarder->pit);
ERR_PIT:
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

    content_store_free(forwarder->content_store);
    pit_free(forwarder->pit);
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

Configuration *
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
forwarder_content_store_set_store(forwarder_t * forwarder, bool val)
{
    assert(forwarder);
    forwarder->store_in_content_store = val;
}

bool
forwarder_content_store_get_store(forwarder_t * forwarder)
{
    assert(forwarder);
    return forwarder->store_in_content_store;
}

void
forwarder_content_store_set_serve(forwarder_t * forwarder, bool val)
{
    assert(forwarder);
    forwarder->serve_from_content_store = val;
}

bool
forwarder_content_store_get_serve(forwarder_t * forwarder)
{
    assert(forwarder);
    return forwarder->serve_from_content_store;
}

void
forwarder_content_store_set_size(forwarder_t * forwarder, size_t size)
{
    assert(forwarder);

    content_store_free(forwarder->content_store);

    // XXX TODO
#if 0
    ContentStoreConfig content_storeConfig = {.objectCapacity =
        maximumContentStoreSize};

    forwarder->content_store =
        content_storeLRU_Create(&content_storeConfig, forwarder->logger);
#endif
}

void
forwarder_content_store_clear(forwarder_t * forwarder)
{
    assert(forwarder);

    content_store_clear(forwarder->content_store);
}

void
forwarder_receive_command(forwarder_t * forwarder, command_type_t command_type,
        uint8_t * packet, unsigned connection_id)
{
    configuration_receive_command(forwarder->config, command_type, packet, connection_id);
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
void
forwarder_drop(forwarder_t * forwarder, msgbuf_t *message)
{
    forwarder->stats.countDropped++;

    switch (msgbuf_get_type(message)) {
        case MESSAGE_TYPE_INTEREST:
            forwarder->stats.countInterestsDropped++;
            break;

        case MESSAGE_TYPE_DATA:
            forwarder->stats.countObjectsDropped++;
            break;

        default:
            break;
    }

    // dont destroy message here, its done at end of receive
}

/*
 *   If the hoplimit is equal to 0, then we may only forward it to local
 * applications.  Otherwise, we may forward it off the system.
 *
 */
static
void
forwarder_forward_via_connection(forwarder_t * forwarder, msgbuf_t * msgbuf,
        unsigned conn_id)
{
    connection_table_t * table = forwarder_get_connection_table(forwarder);
    const connection_t * conn = connection_table_get_by_id(table, conn_id);

    if (!conn) {
        forwarder->stats.countDroppedConnectionNotFound++;
        DEBUG("forward msgbuf %p to interface %u not found (count %u)",
                msgbuf, conn_id, forwarder->stats.countDroppedConnectionNotFound);
        forwarder_drop(forwarder, msgbuf);
        return;
    }

    /* Always queue the packet... */
    bool success = connection_send(conn, msgbuf, true);

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

        DEBUG("forward msgbuf %p to interface %u send failure (count %u)", msgbuf,
                conn_id, forwarder->stats.countSendFailures);
        forwarder_drop(forwarder, msgbuf);
        return;
    }

    switch (msgbuf_get_type(msgbuf)) {
        case MESSAGE_TYPE_INTEREST:
            forwarder->stats.countInterestForwarded++;
            break;

        case MESSAGE_TYPE_DATA:
            forwarder->stats.countObjectsForwarded++;
            break;

        default:
            break;
    }

    DEBUG("forward msgbuf %p to interface %u (int %u, obj %u)", msgbuf,
            conn_id, forwarder->stats.countInterestForwarded,
            forwarder->stats.countObjectsForwarded);

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
        msgbuf_t *msgbuf, const nexthops_t * nexthops)
{
    unsigned forwardedCopies = 0;

    unsigned ingressId = msgbuf_get_connection_id(msgbuf);
    uint32_t old_path_label = 0;

    if (msgbuf_get_type(msgbuf) == MESSAGE_TYPE_DATA)
        old_path_label = msgbuf_get_pathlabel(msgbuf);

    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
        if (nexthop == ingressId)
            continue;

        forwardedCopies++;
        forwarder_forward_via_connection(forwarder, msgbuf, nexthop);

        // everytime we send out a message we need to restore the original path
        // label of the message this is important because we keep a single copy
        // of the message (single pointer) and we modify the path label at each
        // send.
        if (msgbuf_get_type(msgbuf) == MESSAGE_TYPE_DATA)
            msgbuf_set_pathlabel(msgbuf, old_path_label);
    });

    return forwardedCopies;
}


static
bool
forwarder_forward_via_fib(forwarder_t * forwarder, msgbuf_t *msgbuf,
        pit_verdict_t verdict)
{
    assert(forwarder);
    assert(msgbuf);
    assert(msgbuf_get_type(msgbuf) == MESSAGE_TYPE_INTEREST);

    fib_entry_t *fib_entry = fib_match_message(forwarder->fib, msgbuf);
    if (!fib_entry)
        return false;

    // XXX TODO PROBE HOOK MIGHT BE HANDLED ELSEWHERE
    if (msgbuf_is_probe(msgbuf)) {
        connection_table_t * table = forwarder_get_connection_table(forwarder);
        const nexthops_t * nexthops = fib_entry_GetNexthops(fib_entry);

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

    const nexthops_t * nexthops = fib_entry_nexthops_get_from_strategy(fib_entry,
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

    if (forwarder_forward_to_nexthops(forwarder, msgbuf, nexthops) <= 0) {
        DEBUG("Message %p returned an emtpy next hop set", msgbuf);
        return false;
    }
    return true;

}


static
bool
_satisfy_from_content_store(forwarder_t * forwarder, msgbuf_t *interest_msgbuf)
{
    assert(forwarder);
    assert(msgbuf_get_type(msgbuf) == MESSAGE_TYPE_INTEREST);

    if (msgbuf_get_interest_lifetime(interest_msgbuf) == 0)
        return false;

    if (!forwarder->serve_from_content_store)
        return false;

    // See if there's a match in the store.
    msgbuf_t * data_msgbuf = content_store_match(forwarder->content_store,
            interest_msgbuf, ticks_now());

    if (!data_msgbuf)
        return false;

    // Remove it from the PIT.  nexthops is allocated, so need to destroy
    nexthops_t * nexthops = pit_on_data(forwarder->pit, data_msgbuf);
    assert(nexthops); // Illegal state: got a null nexthops for an interest we just inserted

    // send message in reply, then done
    forwarder->stats.countInterestsSatisfiedFromStore++;

    DEBUG("Message %p satisfied from content store (satisfied count %u)",
            interest_msgbuf, forwarder->stats.countInterestsSatisfiedFromStore);

    msgbuf_reset_pathlabel(data_msgbuf);

    forwarder_forward_to_nexthops(forwarder, data_msgbuf, nexthops);

    return true;
}

/**
 * @function forwarder_receive_interest
 * @abstract Receive an interest from the network
 * @discussion
 *   (1) if interest in the PIT, aggregate in PIT
 *   (2) if interest in the ContentStore, reply
 *   (3) if in the FIB, forward
 *   (4) drop
 *
 */
static
void
forwarder_receive_interest(forwarder_t * forwarder, msgbuf_t * msgbuf)
{
    assert(forwarder);
    assert(msgbuf);
    assert(msgbuf_get_type(msgbuf) == MESSAGE_TYPE_INTEREST);
    forwarder->stats.countInterestsReceived++;

    // (1) Try to aggregate in PIT
    pit_verdict_t verdict = pit_on_interest(forwarder->pit, msgbuf);
    switch(verdict) {
        case PIT_VERDICT_AGGREGATE:
            forwarder->stats.countInterestsAggregated++;
            DEBUG("Message %p aggregated in PIT (aggregated count %u)",
                    msgbuf, forwarder->stats.countInterestsAggregated);
            return;

        case PIT_VERDICT_FORWARD:
        case PIT_VERDICT_RETRANSMIT:
            DEBUG("Message %p not aggregated in PIT (aggregated count %u)",
                    msgbuf, forwarder->stats.countInterestsAggregated);
            break;
    }

    // At this point, we just created a PIT entry.  If we don't forward the
    // interest, we need to remove the PIT entry.

    // (2) Try to satisfy from content store
    if (_satisfy_from_content_store(forwarder, msgbuf)) {
        // done
        // If we found a content object in the CS,
        // messageProcess_Satisfy_from_content_store already cleared the PIT state
        return;
    }

    // (3) Try to forward it
    if (forwarder_forward_via_fib(forwarder, msgbuf, verdict)) {
        // done
        return;
    }

    // Remove the PIT entry?
    forwarder->stats.countDroppedNoRoute++;

    DEBUG("Message %p did not match FIB, no route (count %u)",
                msgbuf, forwarder->stats.countDroppedNoRoute);

    forwarder_drop(forwarder, msgbuf);
}

/**
 * @function forwarder_receive_data
 * @abstract Process an in-bound content object
 * @discussion
 *   (1) If it does not match anything in the PIT, drop it
 *   (2) Add to Content Store
 *   (3) Reverse path forward via PIT entries
 *
 * @param <#param1#>
 */
static
void
forwarder_receive_data(forwarder_t * forwarder,
        msgbuf_t *msgbuf)
{
    forwarder->stats.countObjectsReceived++;

    nexthops_t * ingressSetUnion = pit_on_data(forwarder->pit, msgbuf);
    if (!ingressSetUnion) {
        // (1) If it does not match anything in the PIT, drop it
        forwarder->stats.countDroppedNoReversePath++;

        DEBUG("Message %p did not match PIT, no reverse path (count %u)",
                msgbuf, forwarder->stats.countDroppedNoReversePath);

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

        if (forwarder->store_in_content_store && connection_is_local(conn)) {
            content_store_add(forwarder->content_store, msgbuf, ticks_now());
            DEBUG("Message %p store in CS anyway", msgbuf);
        }

        forwarder_drop(forwarder, msgbuf);
    } else {
        // (2) Add to Content Store. Store may remove expired content, if necessary,
        // depending on store policy.
        if (forwarder->store_in_content_store) {
            content_store_add(forwarder->content_store, msgbuf, ticks_now());
        }
        // (3) Reverse path forward via PIT entries
        forwarder_forward_to_nexthops(forwarder, msgbuf, ingressSetUnion);

    }
}


void
forwarder_receive(forwarder_t * forwarder, msgbuf_t * msgbuf, unsigned new_batch)
{
    assert(forwarder);
    assert(msgbuf);

    // this are the checks needed to implement WLDR. We set wldr only on the STAs
    // and we let the AP to react according to choise of the client.
    // if the STA enables wldr using the set command, the AP enable wldr as well
    // otherwise, if the STA disable it the AP remove wldr
    // WLDR should be enabled only on the STAs using the command line
    // TODO
    // disable WLDR command line on the AP
    connection_table_t * table = forwarder_get_connection_table(forwarder);
    connection_t * conn = connection_table_get_by_id(table, msgbuf_get_connection_id(msgbuf));
    if (!conn)
        return;

    if (msgbuf_has_wldr(msgbuf)) {
        if (connection_has_wldr(conn)) {
            // case 1: WLDR is enabled
            connection_wldr_detect_losses(conn, msgbuf);
        } else if (!connection_has_wldr(conn) &&
                connection_wldr_autostart_is_allowed(conn)) {
            // case 2: We are on an AP. We enable WLDR
            connection_wldr_enable(conn, true);
            connection_wldr_detect_losses(conn, msgbuf);
        }
        // case 3: Ignore WLDR
    } else {
        if (connection_has_wldr(conn) && connection_wldr_autostart_is_allowed(conn)) {
            // case 1: STA do not use WLDR, we disable it
            connection_wldr_enable(conn, false);
        }
    }

    forwarder->pending_batch += new_batch - 1;
    forwarder->stats.countReceived++;

    char *nameString = name_ToString(msgbuf_get_name(msgbuf));
    DEBUG( "Message %p ingress %3u length %5u received name %s", msgbuf,
            msgbuf_get_connection_id(msgbuf), msgbuf_get_len(msgbuf), nameString);
    free(nameString);

    switch (msgbuf_get_type(msgbuf)) {
        case MESSAGE_TYPE_INTEREST:
            forwarder_receive_interest(forwarder, msgbuf);
            break;

        case MESSAGE_TYPE_DATA:
            forwarder_receive_data(forwarder, msgbuf);
            break;

        default:
            forwarder_drop(forwarder, msgbuf);
            break;
    }

    /* Send batch ? */
    if (forwarder->pending_batch == 0) {
        const connection_table_t * table = forwarder_get_connection_table(forwarder);
        for (unsigned i = 0; i < forwarder->num_pending_conn; i++) {
            const connection_t *  conn = connection_table_at(table, forwarder->pending_conn[i]);
            // flush
            connection_send(conn, NULL, false);
        }
        forwarder->num_pending_conn = 0;
    }
}

bool
forwarder_add_or_update_route(forwarder_t * forwarder, ip_prefix_t * prefix,
        unsigned ingress_id)
{
    assert(forwarder);
    assert(prefix);

    Configuration *config = forwarder_get_configuration(forwarder);

    char prefix_s[MAXSZ_IP_PREFIX];
    int rc = ip_prefix_snprintf(prefix_s, MAXSZ_IP_PREFIX, prefix);
    assert(rc < MAXSZ_IP_PREFIX);
    if (rc < 0)
        return false;

    // XXX TODO this should store options too
    strategy_type_t strategy_type = configuration_get_strategy(config, prefix_s);

    Name * name_prefix = name_CreateFromAddress(prefix->family,
            prefix->address, prefix->len);
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
    fib_remove(forwarder->fib, name_prefix, ingress_id);
    name_Release(&name_prefix);

    return true;
}

#ifdef WITH_POLICY

bool
forwarder_add_or_update_policy(forwarder_t * forwarder, ip_prefix_t * prefix,
        policy_t * policy)
{
    assert(forwarder);
    assert(prefix);
    assert(policy);

    Name *name_prefix = name_CreateFromAddress(prefix->family, prefix->address,
            prefix->len);
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
    assert(strategy_type_valid(strategy_type));
    /* strategy_options might be NULL */

    fib_entry_t * entry = fib_contains(forwarder->fib, name_prefix);
    if (!entry)
        return;

    fib_entry_set_strategy(entry, strategy_type, strategy_options);
}

content_store_t *
forwarder_get_content_store(const forwarder_t * forwarder)
{
    assert(forwarder);

    return forwarder->content_store;
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
forwarder_get_fib(forwarder_t * forwarder) {
    return forwarder->fib;
}

#ifdef WITH_MAPME
void
forwarder_on_connection_event(forwarder_t * forwarder,
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

/* Main hook handler */

/**
 * \brief Handle incoming messages
 * \param [in] forwarder - Reference to the Forwarder instance
 * \param [in] packet - Packet buffer
 * \param [in] conn_id - A hint on the connection ID on which the packet
 *      was received
 * \return Flag indicating whether the packet matched a hook and was
 *      (successfully or not) processed.
 */
bool
forwarder_handle_hooks(const forwarder_t * forwarder, uint8_t * packet,
        listener_t * listener, int fd, unsigned conn_id, address_pair_t * pair)
{
    bool is_matched = false;

    /* BEGIN Match */

#ifdef WITH_MAPME
    bool is_mapme = mapme_match_packet(packet);
    is_matched |= is_mapme;
#endif /* WITH_MAPME */

    /* ... */

    /* END Match */

    if (!is_matched)
        return false;

    /*
     * Find existing connection or create a new one (we assume all processing
     * requires a valid connection.
     */

    /* Find connection and eventually create it */
    if (conn_id == CONNECTION_ID_UNDEFINED)
        conn_id = listener_create_connection(listener, fd, pair);

    /* BEGIN Process */

#ifdef WITH_MAPME
    if (is_mapme)
        mapme_process(forwarder->mapme, packet, conn_id);
#endif /* WITH_MAPME */

    /* ... */

    /* END Process */

    return true;
}

