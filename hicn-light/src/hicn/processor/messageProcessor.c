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
#include <hicn/util/log.h>
#include <stdio.h>
#include <string.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Memory.h>
#include <hicn/core/connection.h>
#include <hicn/processor/messageProcessor.h>

#include <hicn/processor/fib.h>

#include <hicn/base/content_store.h>
#include <hicn/base/pit.h>

//#include <hicn/strategies/strategyImpl.h>

#include <hicn/io/streamConnection.h>
#include <hicn/io/udpListener.h>

#include <parc/assert/parc_Assert.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

#include <hicn/core/messageHandler.h>

#define DEFAULT_PIT_SIZE 65535

typedef struct processor_stats {
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
} _ProcessorStats;

struct message_processor {
    Forwarder *forwarder;
    Logger *logger;

    pit_t * pit;
    content_store_t * content_store;
    FIB *fib;

    bool store_in_cache;
    bool serve_from_cache;

    _ProcessorStats stats;

    /*
     * The message processor has to decide whether to queue incoming packets for
     * batching, or trigger the transmission on the connection
     */
    unsigned pending_batch;
    unsigned pending_conn[MAX_MSG];
    size_t num_pending_conn;
};

static void messageProcessor_Drop(MessageProcessor *processor,
        msgbuf_t *message);
static void messageProcessor_ReceiveInterest(MessageProcessor *processor,
        msgbuf_t *interestMessage);
static void messageProcessor_ReceiveContentObject(MessageProcessor *processor,
        msgbuf_t *objectMessage);
static unsigned messageProcessor_ForwardToNexthops(MessageProcessor *processor,
        msgbuf_t *message, const nexthops_t * nexthops);
static void messageProcessor_ForwardToInterfaceId(MessageProcessor *processor,
        msgbuf_t *message, unsigned interfaceId);

// ============================================================
// Public API

    MessageProcessor *
messageProcessor_Create(Forwarder *forwarder)
{
    size_t objectStoreSize =
        configuration_GetObjectStoreSize(forwarder_GetConfiguration(forwarder));

    MessageProcessor *processor =
        parcMemory_AllocateAndClear(sizeof(MessageProcessor));
    parcAssertNotNull(processor, "parcMemory_AllocateAndClear(%zu) returned NULL",
            sizeof(MessageProcessor));
    memset(processor, 0, sizeof(MessageProcessor));

    processor->forwarder = forwarder;
    processor->logger = logger_Acquire(forwarder_GetLogger(forwarder));
    processor->pit = pit_create(DEFAULT_PIT_SIZE);

    processor->fib = fib_Create(forwarder);

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                PARCLogLevel_Debug)) {
        logger_Log(processor->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                __func__, "MessageProcessor %p created", (void *)processor);
    }

    processor->content_store = content_store_create(CONTENT_STORE_TYPE_LRU, objectStoreSize);

    // the two flags for the cache are set to true by default. If the cache
    // is active it always work as expected unless the use modifies this
    // values using controller
    processor->store_in_cache = true;
    processor->serve_from_cache = true;

    return processor;
}

void
messageProcessor_SetContentObjectStoreSize(MessageProcessor *processor, size_t maximumContentStoreSize)
{
    parcAssertNotNull(processor, "Parameter processor must be non-null");
    content_store_free(processor->content_store);

    // XXX TODO
#if 0
    ContentStoreConfig content_storeConfig = {.objectCapacity =
        maximumContentStoreSize};

    processor->content_store =
        content_storeLRU_Create(&content_storeConfig, processor->logger);
#endif
}

void
messageProcessor_ClearCache(MessageProcessor *processor)
{
    assert(processor);
    content_store_clear(processor->content_store);
}

    content_store_t *
messageProcessor_GetContentStore(const MessageProcessor *processor)
{
    parcAssertNotNull(processor, "Parameter processor must be non-null");
    return processor->content_store;
}

void
messageProcessor_Destroy(MessageProcessor **processorPtr)
{
    parcAssertNotNull(processorPtr, "Parameter must be non-null double pointer");
    parcAssertNotNull(*processorPtr, "Parameter dereference to non-null pointer");

    MessageProcessor *processor = *processorPtr;

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                PARCLogLevel_Debug)) {
        logger_Log(processor->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                __func__, "MessageProcessor %p destroyed", (void *)processor);
    }

    logger_Release(&processor->logger);
    fib_Destroy(&processor->fib);
    content_store_free(processor->content_store);
    pit_free(processor->pit);

    parcMemory_Deallocate((void **)&processor);
    *processorPtr = NULL;
}

/* Flush connections that have pending packets to be sent */
void
messageProcessor_FlushConnections(MessageProcessor *processor)
{
    const connection_table_t * table = forwarder_GetConnectionTable(processor->forwarder);
    for (unsigned i = 0; i < processor->num_pending_conn; i++) {
        const Connection * conn = connection_table_at(table, processor->pending_conn[i]);
        // flush
        connection_Send(conn, NULL, false);
    }
    processor->num_pending_conn = 0;
}

void
messageProcessor_Receive(MessageProcessor *processor, msgbuf_t *message, unsigned new_batch)
{
    parcAssertNotNull(processor, "Parameter processor must be non-null");
    parcAssertNotNull(message, "Parameter message must be non-null");

    processor->stats.countReceived++;

    if (new_batch > 0) {
        processor->pending_batch += new_batch - 1;
    } else {
        processor->pending_batch--;
    }

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                PARCLogLevel_Debug)) {
        char *nameString = name_ToString(msgbuf_name(message));
        logger_Log(processor->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                __func__, "Message %p ingress %3u length %5u received name %s",
                (void *)message, msgbuf_connection_id(message),
                msgbuf_len(message), nameString);
        parcMemory_Deallocate((void **)&nameString);
    }

    switch (msgbuf_type(message)) {
        case MessagePacketType_Interest:
            messageProcessor_ReceiveInterest(processor, message);
            break;

        case MessagePacketType_ContentObject:
            messageProcessor_ReceiveContentObject(processor, message);
            break;

        default:
            messageProcessor_Drop(processor, message);
            break;
    }

    /* Send batch ? */
    if (processor->pending_batch == 0)
        messageProcessor_FlushConnections(processor);
}

    bool
messageProcessor_add_or_update_route(MessageProcessor *processor,
        add_route_command *control, unsigned ifidx)
{
    Configuration *config = forwarder_GetConfiguration(processor->forwarder);

    char *prefixStr = (char *) utils_PrefixLenToString( control->family,
            &control->address, &control->len);
    // XXX TODO this should store options too
    strategy_type_t strategy_type = configuration_GetForwardingStrategy(config, prefixStr);

    Name *prefix = name_CreateFromAddress(control->family, control->address,
            control->len);
    fib_entry_t *entry = fib_Contains(processor->fib, prefix);
    if (!entry) {
        entry = fib_entry_Create(prefix, strategy_type, NULL, processor->forwarder);
        fib_entry_nexthops_add(entry, ifidx);
        fib_Add(processor->fib, entry);
    } else {
        fib_entry_nexthops_add(entry, ifidx);
    }

    free(prefixStr);
    name_Release(&prefix);

    return true;
}

    bool
messageProcessor_RemoveRoute(MessageProcessor *processor,
        remove_route_command *control, unsigned ifidx)
{
    Name *name = name_CreateFromAddress(control->family, control->address,
            control->len);
    fib_Remove(processor->fib, name, ifidx);
    name_Release(&name);

    return true;
}

#ifdef WITH_POLICY

    bool
messageProcessor_add_or_update_policy(MessageProcessor *processor,
        add_policy_command *control)
{
    Name *prefix = name_CreateFromAddress(control->family, control->address,
            control->len);
    fib_entry_t *entry = fib_Contains(processor->fib, prefix);
    if (!entry)
        return false;
    fib_entry_SetPolicy(entry, control->policy);

    name_Release(&prefix);

    return true;
}

    bool
messageProcessor_RemovePolicy(MessageProcessor *processor,
        remove_policy_command *control)
{
    Name *prefix = name_CreateFromAddress(control->family, control->address,
            control->len);
    fib_entry_t *entry = fib_Contains(processor->fib, prefix);
    name_Release(&prefix);

    if (!entry)
        return false;

    fib_entry_SetPolicy(entry, POLICY_NONE);

    return true;
}

#endif /* WITH_POLICY */

void
messageProcessor_RemoveConnectionIdFromRoutes(MessageProcessor *processor,
        unsigned connectionId)
{
    fib_RemoveConnectionId(processor->fib, connectionId);
}

void
processor_SetStrategy(MessageProcessor *processor, Name *prefix,
        strategy_type_t strategy_type, strategy_options_t * strategy_options)
{
    fib_entry_t *entry = fib_Contains(processor->fib, prefix);
    if (entry != NULL) {
        fib_entry_SetStrategy(entry, strategy_type, strategy_options);
    }
}

    fib_entry_list_t *
messageProcessor_GetFibEntries(MessageProcessor *processor)
{
    parcAssertNotNull(processor, "Parameter processor must be non-null");
    return fib_GetEntries(processor->fib);
}

// ============================================================
// Internal API

/**
 * @function messageProcessor_Drop
 * @abstract Whenever we "drop" a message, increment countes
 * @discussion
 *   This is a bookkeeping function.  It increments the appropriate counters.
 *
 *   The default action for a message is to destroy it in
 * <code>messageProcessor_Receive()</code>, so this function does not need to do
 * that.
 *
 */
static
void
messageProcessor_Drop(MessageProcessor *processor, msgbuf_t *message)
{
    processor->stats.countDropped++;

    switch (msgbuf_type(message)) {
        case MessagePacketType_Interest:
            processor->stats.countInterestsDropped++;
            break;

        case MessagePacketType_ContentObject:
            processor->stats.countObjectsDropped++;
            break;

        default:
            break;
    }

    // dont destroy message here, its done at end of receive
}

/**
 * @function messageProcessor_AggregateInterestInPit
 * @abstract Try to aggregate the interest in the PIT
 * @discussion
 *   Tries to aggregate the interest with another interest.
 *
 * @return true if interest aggregagted (no more forwarding needed), false if
 * need to keep processing it.
 */
static
pit_verdict_t
messageProcessor_AggregateInterestInPit(MessageProcessor *processor,
        msgbuf_t *msgbuf)
{
    assert(processor);
    assert(msgbuf);
    assert(msgbuf_type(msgbuf) == MessagePacketType_Interest);

    pit_verdict_t verdict = pit_on_interest(processor->pit, msgbuf);
    if (verdict == PIT_VERDICT_AGGREGATE) {
        processor->stats.countInterestsAggregated++;
        DEBUG("Message %p aggregated in PIT (aggregated count %u)",
                msgbuf, processor->stats.countInterestsAggregated);
        return true;
    }

    DEBUG("Message %p not aggregated in PIT (aggregated count %u)",
            msgbuf, processor->stats.countInterestsAggregated);
    return false;
}

static
bool
_satisfyFromContentStore(MessageProcessor *processor, msgbuf_t *interestMessage)
{
    if (msgbuf_interest_lifetime(interestMessage) == 0)
        return false;

    if (!processor->serve_from_cache)
        return false;

    // See if there's a match in the store.
    msgbuf_t *objectMessage = content_store_match(processor->content_store,
            interestMessage, forwarder_GetTicks(processor->forwarder));

    if (!objectMessage)
        return false;

    // Remove it from the PIT.  nexthops is allocated, so need to destroy
    nexthops_t * nexthops = pit_on_data(processor->pit, objectMessage);
    assert(nexthops); // Illegal state: got a null nexthops for an interest we just inserted

    // send message in reply, then done
    processor->stats.countInterestsSatisfiedFromStore++;

    DEBUG("Message %p satisfied from content store (satisfied count %u)",
            interestMessage, processor->stats.countInterestsSatisfiedFromStore);

    msgbuf_reset_pathlabel(objectMessage);

    messageProcessor_ForwardToNexthops(processor, objectMessage, nexthops);

    return true;
}

/**
 * @function messageProcessor_ForwardViaFib
 * @abstract Try to forward the interest via the FIB
 * @discussion
 *   This calls <code>messageProcessor_ForwardToNexthops()</code>, so if we find
 * any nexthops, the interest will be sent on its way.  Depending on the
 * IoOperations of each nexthop, it may be a deferred write and bump up the
 * <code>interestMessage</code> refernce count, or it may copy the data out.
 *
 *   A TRUE return means we did our best to forward it via the routes.  If those
 * routes are actually down or have errors, we still return TRUE.  A FALSE
 * return means there were no routes to try.
 *
 * @return true if we found a route and tried to forward it, false if no route
 */
static
bool
messageProcessor_ForwardViaFib(MessageProcessor *processor,
        msgbuf_t *msgbuf, pit_verdict_t verdict)
{
    assert(processor);
    assert(msgbuf);
    assert(msgbuf_type(msgbuf) == MessagePacketType_Interest);

    fib_entry_t *fib_entry = fib_MatchMessage(processor->fib, msgbuf);
    if (!fib_entry)
        return false;

    // XXX TODO PROBE HOOK MIGHT BE HANDLED ELSEWHERE
    if (msgbuf_is_probe(msgbuf)) {
        connection_table_t * table = forwarder_GetConnectionTable(processor->forwarder);
        const nexthops_t * nexthops = fib_entry_GetNexthops(fib_entry);

        unsigned nexthop;
        nexthops_foreach(nexthops, nexthop, {
            Connection *conn = connection_table_at(table, nexthop);
            if (!conn)
                continue;
            if (!connection_IsLocal(conn))
                continue;
            Connection * replyConn = connection_table_get_by_id(table,
                    msgbuf_connection_id(msgbuf));
            connection_HandleProbe(replyConn, msgbuf_packet(msgbuf));
            return false;
        });
    }

    pit_entry_t * entry = pit_lookup(processor->pit, msgbuf);
    if (!entry)
        return false;

    pit_entry_fib_entry(entry) = fib_entry;

    const nexthops_t * nexthops = fib_entry_GetNexthopsFromForwardingStrategy(fib_entry,
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

    if (messageProcessor_ForwardToNexthops(processor, msgbuf, nexthops) <= 0) {
        DEBUG("Message %p returned an emtpy next hop set", msgbuf);
        return false;
    }
    return true;

}

/**
 * @function messageProcessor_ReceiveInterest
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
messageProcessor_ReceiveInterest(MessageProcessor *processor,
        msgbuf_t *interestMessage)
{
    processor->stats.countInterestsReceived++;

    // (1) Try to aggregate in PIT
    pit_verdict_t verdict = messageProcessor_AggregateInterestInPit(processor, interestMessage);
    switch(verdict) {
        case PIT_VERDICT_AGGREGATE:
            return;

        case PIT_VERDICT_FORWARD:
        case PIT_VERDICT_RETRANSMIT:
            break;
    }

    // At this point, we just created a PIT entry.  If we don't forward the
    // interest, we need to remove the PIT entry.

    // (2) Try to satisfy from content store
    if (_satisfyFromContentStore(processor, interestMessage)) {
        // done
        // If we found a content object in the CS,
        // messageProcess_SatisfyFromContentStore already cleared the PIT state
        return;
    }

    // (3) Try to forward it
    if (messageProcessor_ForwardViaFib(processor, interestMessage, verdict)) {
        // done
        return;
    }

    // Remove the PIT entry?
    processor->stats.countDroppedNoRoute++;

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                PARCLogLevel_Debug)) {
        logger_Log(processor->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
                __func__, "Message %p did not match FIB, no route (count %u)",
                (void *)interestMessage, processor->stats.countDroppedNoRoute);
    }

    messageProcessor_Drop(processor, interestMessage);
}

/**
 * @function messageProcessor_ReceiveContentObject
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
messageProcessor_ReceiveContentObject(MessageProcessor *processor,
        msgbuf_t *msgbuf)
{
    processor->stats.countObjectsReceived++;

    nexthops_t * ingressSetUnion = pit_on_data(processor->pit, msgbuf);
    if (!ingressSetUnion) {
        // (1) If it does not match anything in the PIT, drop it
        processor->stats.countDroppedNoReversePath++;

        DEBUG("Message %p did not match PIT, no reverse path (count %u)",
                msgbuf, processor->stats.countDroppedNoReversePath);

        // MOVE PROBE HOOK ELSEWHERE
        // XXX relationship with forwarding strategy... insert hooks
        // if the packet is a probe we need to analyze it
        // NOTE : probes are not stored in PIT
        if (msgbuf_is_probe(msgbuf)) {
            fib_entry_t *fibEntry = fib_MatchMessage(processor->fib, msgbuf);
            if(fibEntry && fib_entry_strategy_type(fibEntry) == STRATEGY_TYPE_LOW_LATENCY) {
                nexthops_t probe_nexthops;
                nexthops_add(&probe_nexthops, msgbuf_connection_id(msgbuf));
                fib_entry_ReceiveObjectMessage(fibEntry, &probe_nexthops, msgbuf, 0,
                        forwarder_GetTicks(processor->forwarder));

                // XXX TODO CONFIRM WE DON'T EXIT HERE ?
            }
        }

        // we store the packets in the content store enven in the case where there
        // is no match in the PIT table in this way the applications can push the
        // content in the CS of the forwarder. We allow this only for local faces
        const connection_table_t * table = forwarder_GetConnectionTable(processor->forwarder);
        const Connection * conn = connection_table_get_by_id(table, msgbuf_connection_id(msgbuf));

        if (processor->store_in_cache && connection_IsLocal(conn)) {
            uint64_t now = forwarder_GetTicks(processor->forwarder);
            content_store_add(processor->content_store, msgbuf, now);
            DEBUG("Message %p store in CS anyway", msgbuf);
        }

        messageProcessor_Drop(processor, msgbuf);
    } else {
        // (2) Add to Content Store. Store may remove expired content, if necessary,
        // depending on store policy.
        if (processor->store_in_cache) {
            uint64_t now = forwarder_GetTicks(processor->forwarder);
            content_store_add(processor->content_store, msgbuf, now);
        }
        // (3) Reverse path forward via PIT entries
        messageProcessor_ForwardToNexthops(processor, msgbuf, ingressSetUnion);

    }
}

/**
 * @function messageProcessor_ForwardToNexthops
 * @abstract Try to forward to each nexthop listed in the NumberSet
 * @discussion
 *   Will not forward to the ingress connection.
 *
 * @return The number of nexthops tried
 */
static
    unsigned
messageProcessor_ForwardToNexthops(MessageProcessor *processor,
        msgbuf_t *msgbuf, const nexthops_t * nexthops)
{
    unsigned forwardedCopies = 0;

    unsigned ingressId = msgbuf_connection_id(msgbuf);
    uint32_t old_path_label = 0;

    if (msgbuf_type(msgbuf) == MessagePacketType_ContentObject)
        old_path_label = msgbuf_get_pathlabel(msgbuf);

    unsigned nexthop;
    nexthops_foreach(nexthops, nexthop, {
            if (nexthop == ingressId)
            continue;

            forwardedCopies++;
            messageProcessor_ForwardToInterfaceId(processor, msgbuf, nexthop);

            // everytime we send out a message we need to restore the original path
            // label of the message this is important because we keep a single copy
            // of the message (single pointer) and we modify the path label at each
            // send.
            if (msgbuf_type(msgbuf) == MessagePacketType_ContentObject)
            msgbuf_set_pathlabel(msgbuf, old_path_label);
            });

    return forwardedCopies;
}

/**
 * caller has checked that the hop limit is ok.  Try to send out the connection.
 */
static
void
messageProcessor_SendWithGoodHopLimit(MessageProcessor *processor,
        msgbuf_t * msgbuf, unsigned interfaceId, const Connection *conn)
{
    /* Always queue the packet... */
    bool success = connection_Send(conn, msgbuf, true);

    /* ... and mark the connection as pending if this is not yet the case */
    unsigned conn_id = connection_GetConnectionId(conn);
    unsigned i;
    for (i = 0; i < processor->num_pending_conn; i++) {
        if (processor->pending_conn[i] == conn_id)
            break;
    }
    if (i == processor->num_pending_conn)
        processor->pending_conn[processor->num_pending_conn++] = conn_id;

    if (!success) {
        processor->stats.countSendFailures++;

        DEBUG("forward msgbuf %p to interface %u send failure (count %u)", msgbuf,
                interfaceId, processor->stats.countSendFailures);
        messageProcessor_Drop(processor, msgbuf);
        return;
    }

    switch (msgbuf_type(msgbuf)) {
        case MessagePacketType_Interest:
            processor->stats.countInterestForwarded++;
            break;

        case MessagePacketType_ContentObject:
            processor->stats.countObjectsForwarded++;
            break;

        default:
            break;
    }

    DEBUG("forward msgbuf %p to interface %u (int %u, obj %u)", msgbuf,
            interfaceId, processor->stats.countInterestForwarded,
            processor->stats.countObjectsForwarded);
}

/*
 *   If the hoplimit is equal to 0, then we may only forward it to local
 * applications.  Otherwise, we may forward it off the system.
 *
 */
static
void
messageProcessor_ForwardToInterfaceId(MessageProcessor *processor,
        msgbuf_t *message, unsigned interfaceId)
{
    connection_table_t * table = forwarder_GetConnectionTable(processor->forwarder);
    const Connection *conn = connection_table_get_by_id(table, interfaceId);

    if (!conn) {
        processor->stats.countDroppedConnectionNotFound++;
        DEBUG("forward message %p to interface %u not found (count %u)",
                message, interfaceId, processor->stats.countDroppedConnectionNotFound);
        messageProcessor_Drop(processor, message);
        return;
    }
    messageProcessor_SendWithGoodHopLimit(processor, message, interfaceId, conn);
}

void
messageProcessor_SetCacheStoreFlag(MessageProcessor *processor, bool val)
{
    processor->store_in_cache = val;
}

bool
messageProcessor_GetCacheStoreFlag(MessageProcessor *processor)
{
    return processor->store_in_cache;
}

void
messageProcessor_SetCacheServeFlag(MessageProcessor *processor, bool val)
{
    processor->serve_from_cache = val;
}

bool
messageProcessor_GetCacheServeFlag(MessageProcessor *processor)
{
    return processor->serve_from_cache;
}

#ifdef WITH_MAPME

FIB *
messageProcessor_getFib(MessageProcessor *processor)
{
    return processor->fib;
}

#endif /* WITH_MAPME */
