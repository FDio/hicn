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
#include <string.h>

#include <parc/algol/parc_ArrayList.h>
#include <parc/algol/parc_Memory.h>
#ifdef WITH_POLICY
#include <parc/algol/parc_EventTimer.h>
#ifdef WITH_MAPME
#include <hicn/core/connection.h>
#endif /* WITH_MAPME */
#endif /* WITH_POLICY */
#include <hicn/processor/messageProcessor.h>

#include <hicn/processor/fib.h>
#include <hicn/processor/pitStandard.h>

#include <hicn/content_store/contentStoreInterface.h>
#include <hicn/content_store/contentStoreLRU.h>

#include <hicn/strategies/loadBalancer.h>
#include <hicn/strategies/lowLatency.h>
#include <hicn/strategies/rnd.h>
#include <hicn/strategies/strategyImpl.h>

#include <hicn/io/streamConnection.h>
#include <hicn/io/udpListener.h>

#include <parc/assert/parc_Assert.h>

#include <hicn/utils/commands.h>
#include <hicn/utils/utils.h>

#include <hicn/utils/address.h>
#include <hicn/core/messageHandler.h>

#ifdef WITH_POLICY
#define STATS_INTERVAL 1000 /* ms */
#endif /* WITH_POLICY */

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

  PIT *pit;
  ContentStoreInterface *contentStore;
  FIB *fib;

  bool store_in_cache;
  bool serve_from_cache;

  _ProcessorStats stats;

#ifdef WITH_POLICY
  void * timer;
#endif /* WITH_POLICY */
};

static void messageProcessor_Drop(MessageProcessor *processor,
                                  Message *message);
static void messageProcessor_ReceiveInterest(MessageProcessor *processor,
                                             Message *interestMessage);
static void messageProcessor_ReceiveContentObject(MessageProcessor *processor,
                                                  Message *objectMessage);
static unsigned messageProcessor_ForwardToNexthops(MessageProcessor *processor,
                                                   Message *message,
                                                   const NumberSet *nexthops);

static void messageProcessor_ForwardToInterfaceId(MessageProcessor *processor,
                                                  Message *message,
                                                  unsigned interfaceId);

// ============================================================
// Public API

#ifdef WITH_POLICY
static void
messageProcessor_Tick(int fd, PARCEventType type, void *user_data)
{
  MessageProcessor *processor = (MessageProcessor*)user_data;
  uint64_t now = (uint64_t)forwarder_GetTicks(processor->forwarder);

  /* Loop over FIB entries to compute statistics from counters */
  FibEntryList *fibList = forwarder_GetFibEntries(processor->forwarder);

  for (size_t i = 0; i < fibEntryList_Length(fibList); i++) {
    FibEntry *entry = (FibEntry *)fibEntryList_Get(fibList, i);
    fibEntry_UpdateStats(entry, now);
  }

  fibEntryList_Destroy(&fibList);
}
#endif /* WITH_POLICY */

MessageProcessor *messageProcessor_Create(Forwarder *forwarder) {
  size_t objectStoreSize =
      configuration_GetObjectStoreSize(forwarder_GetConfiguration(forwarder));

  MessageProcessor *processor =
      parcMemory_AllocateAndClear(sizeof(MessageProcessor));
  parcAssertNotNull(processor, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(MessageProcessor));
  memset(processor, 0, sizeof(MessageProcessor));

  processor->forwarder = forwarder;
  processor->logger = logger_Acquire(forwarder_GetLogger(forwarder));
  processor->pit = pitStandard_Create(forwarder);

  processor->fib = fib_Create(forwarder);

  if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                        PARCLogLevel_Debug)) {
    logger_Log(processor->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
               __func__, "MessageProcessor %p created", (void *)processor);
  }

  ContentStoreConfig contentStoreConfig = {
      .objectCapacity = objectStoreSize,
  };

  processor->contentStore =
      contentStoreLRU_Create(&contentStoreConfig, processor->logger);

  // the two flags for the cache are set to true by default. If the cache
  // is active it always work as expected unless the use modifies this
  // values using controller
  processor->store_in_cache = true;
  processor->serve_from_cache = true;

#ifdef WITH_POLICY
  /* Create statistics timer */
  Dispatcher *dispatcher = forwarder_GetDispatcher(forwarder);
  if (!dispatcher)
    goto ERR;
  processor->timer = dispatcher_CreateTimer(dispatcher, /* repeat */ true,
          messageProcessor_Tick, processor);
  if (!processor->timer)
      goto ERR;
  struct timeval timeout = {STATS_INTERVAL / 1000, (STATS_INTERVAL % 1000) * 1000};
  dispatcher_StartTimer(dispatcher, processor->timer, &timeout);
ERR:
#endif /* WITH_POLICY */

  return processor;
}

void messageProcessor_SetContentObjectStoreSize(
    MessageProcessor *processor, size_t maximumContentStoreSize) {
  parcAssertNotNull(processor, "Parameter processor must be non-null");
  contentStoreInterface_Release(&processor->contentStore);

  ContentStoreConfig contentStoreConfig = {.objectCapacity =
                                               maximumContentStoreSize};

  processor->contentStore =
      contentStoreLRU_Create(&contentStoreConfig, processor->logger);
}

void messageProcessor_ClearCache(MessageProcessor *processor) {
  parcAssertNotNull(processor, "Parameter processor must be non-null");
  size_t objectStoreSize = configuration_GetObjectStoreSize(
      forwarder_GetConfiguration(processor->forwarder));

  contentStoreInterface_Release(&processor->contentStore);

  ContentStoreConfig contentStoreConfig = {
      .objectCapacity = objectStoreSize,
  };

  processor->contentStore =
      contentStoreLRU_Create(&contentStoreConfig, processor->logger);
}

ContentStoreInterface *messageProcessor_GetContentObjectStore(
    const MessageProcessor *processor) {
  parcAssertNotNull(processor, "Parameter processor must be non-null");
  return processor->contentStore;
}

void messageProcessor_Destroy(MessageProcessor **processorPtr) {
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
  contentStoreInterface_Release(&processor->contentStore);
  pit_Release(&processor->pit);

#ifdef WITH_POLICY
  Dispatcher *dispatcher = forwarder_GetDispatcher(processor->forwarder);
  if (!dispatcher)
    goto ERR;
  dispatcher_StopTimer(dispatcher, processor->timer);
  dispatcher_DestroyTimerEvent(dispatcher, (PARCEventTimer**)&processor->timer);
ERR:
#endif /* WITH_POLICY */

  parcMemory_Deallocate((void **)&processor);
  *processorPtr = NULL;
}

void messageProcessor_Receive(MessageProcessor *processor, Message *message) {
  parcAssertNotNull(processor, "Parameter processor must be non-null");
  parcAssertNotNull(message, "Parameter message must be non-null");

  processor->stats.countReceived++;

  if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                        PARCLogLevel_Debug)) {
    char *nameString = name_ToString(message_GetName(message));
    logger_Log(processor->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
               __func__, "Message %p ingress %3u length %5u received name %s",
               (void *)message, message_GetIngressConnectionId(message),
               message_Length(message), nameString);
    parcMemory_Deallocate((void **)&nameString);
  }

  switch (message_GetType(message)) {
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

  // if someone wanted to save it, they made a copy
  message_Release(&message);
}

bool messageProcessor_AddOrUpdateRoute(MessageProcessor *processor,
                                       add_route_command *control,
                                       unsigned ifidx) {
  Configuration *config = forwarder_GetConfiguration(processor->forwarder);

  char *prefixStr = (char *) utils_PrefixLenToString(
      control->addressType, &control->address, &control->len);
  hicn_strategy_t fwdStrategy =
      configuration_GetForwardingStrategy(config, prefixStr);

  Name *prefix = name_CreateFromAddress(control->addressType, control->address,
                                        control->len);
  FibEntry *entry = fib_Contains(processor->fib, prefix);
  if (entry != NULL) {
    fibEntry_AddNexthop(entry, ifidx);
  } else {
#ifdef WITH_POLICY
    entry = fibEntry_Create(prefix, fwdStrategy, processor->forwarder);
#else
    entry = fibEntry_Create(prefix, fwdStrategy);
#endif /* WITH_POLICY */
    fibEntry_AddNexthop(entry, ifidx);
    fib_Add(processor->fib, entry);
  }

  free(prefixStr);
  name_Release(&prefix);

  return true;
}

bool messageProcessor_RemoveRoute(MessageProcessor *processor,
                                  remove_route_command *control,
                                  unsigned ifidx) {
  Name *name = name_CreateFromAddress(control->addressType, control->address,
                                      control->len);
  fib_Remove(processor->fib, name, ifidx);
  name_Release(&name);

  return true;
}

#ifdef WITH_POLICY

bool messageProcessor_AddOrUpdatePolicy(MessageProcessor *processor,
                                       add_policy_command *control) {
  Configuration *config = forwarder_GetConfiguration(processor->forwarder);

  const char *prefixStr = utils_PrefixLenToString(
      control->addressType, &control->address, &control->len);

  Name *prefix = name_CreateFromAddress(control->addressType, control->address,
                                        control->len);
  FibEntry *entry = fib_Contains(processor->fib, prefix);
  if (!entry) {
    hicn_strategy_t fwdStrategy =
        configuration_GetForwardingStrategy(config, prefixStr);
    entry = fibEntry_Create(prefix, fwdStrategy, processor->forwarder);
    fib_Add(processor->fib, entry);
  }
  fibEntry_SetPolicy(entry, control->policy);

  name_Release(&prefix);

  return true;
}

bool messageProcessor_RemovePolicy(MessageProcessor *processor,
                                  remove_policy_command *control) {
  Name *prefix = name_CreateFromAddress(control->addressType, control->address,
                                      control->len);
  FibEntry *entry = fib_Contains(processor->fib, prefix);
  name_Release(&prefix);

  if (!entry)
      return false;

  fibEntry_SetPolicy(entry, POLICY_NONE);

  return true;
}

#endif /* WITH_POLICY */

void messageProcessor_RemoveConnectionIdFromRoutes(MessageProcessor *processor,
                                                   unsigned connectionId) {
  fib_RemoveConnectionId(processor->fib, connectionId);
}

void processor_SetStrategy(MessageProcessor *processor, Name *prefix,
                           hicn_strategy_t strategy,
                           unsigned related_prefixes_len,
                           Name **related_prefixes){
  FibEntry *entry = fib_Contains(processor->fib, prefix);
  if (entry != NULL) {
    fibEntry_SetStrategy(entry, strategy, related_prefixes_len,
                        related_prefixes);
  }
}

FibEntryList *messageProcessor_GetFibEntries(MessageProcessor *processor) {
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
static void messageProcessor_Drop(MessageProcessor *processor,
                                  Message *message) {
  processor->stats.countDropped++;

  switch (message_GetType(message)) {
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
#ifdef WITH_POLICY
static PITVerdict messageProcessor_AggregateInterestInPit(MessageProcessor *processor,
                                                    Message *interestMessage) {
#else
static bool messageProcessor_AggregateInterestInPit(MessageProcessor *processor,
                                                    Message *interestMessage) {
#endif /* WITH_POLICY */
  PITVerdict verdict = pit_ReceiveInterest(processor->pit, interestMessage);

  if (verdict == PITVerdict_Aggregate) {
    // PIT has it, we're done
    processor->stats.countInterestsAggregated++;

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(
          processor->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
          __func__, "Message %p aggregated in PIT (aggregated count %u)",
          (void *)interestMessage, processor->stats.countInterestsAggregated);
    }

    return true;
  }

  if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                        PARCLogLevel_Debug)) {
    logger_Log(
        processor->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
        __func__, "Message %p not aggregated in PIT (aggregated count %u)",
        (void *)interestMessage, processor->stats.countInterestsAggregated);
  }

  return false;
}

static bool _satisfyFromContentStore(MessageProcessor *processor,
                                     Message *interestMessage) {
  bool result = false;

  if (message_GetInterestLifetimeTicks(interestMessage) == 0) {
    return false;
  }

  if (!processor->serve_from_cache) {
    return result;
  }

  // See if there's a match in the store.
  Message *objectMessage = contentStoreInterface_MatchInterest(
      processor->contentStore, interestMessage,
      forwarder_GetTicks(processor->forwarder));

  if (objectMessage != NULL) {
    // Remove it from the PIT.  nexthops is allocated, so need to destroy
    NumberSet *nexthops = pit_SatisfyInterest(processor->pit, objectMessage);
    parcAssertNotNull(
        nexthops,
        "Illegal state: got a null nexthops for an interest we just inserted.");

    // send message in reply, then done
    processor->stats.countInterestsSatisfiedFromStore++;

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(processor->logger, LoggerFacility_Processor,
                 PARCLogLevel_Debug, __func__,
                 "Message %p satisfied from content store (satisfied count %u)",
                 (void *)interestMessage,
                 processor->stats.countInterestsSatisfiedFromStore);
    }

    message_ResetPathLabel(objectMessage);

    messageProcessor_ForwardToNexthops(processor, objectMessage, nexthops);
    numberSet_Release(&nexthops);

    result = true;
  }

  return result;
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
#ifdef WITH_POLICY
static bool messageProcessor_ForwardViaFib(MessageProcessor *processor,
    Message *interestMessage, PITVerdict verdict) {
#else
static bool messageProcessor_ForwardViaFib(MessageProcessor *processor,
                                           Message *interestMessage) {
#endif /* WITH_POLICY */
  FibEntry *fibEntry = fib_MatchMessage(processor->fib, interestMessage);
  if (fibEntry == NULL) {
    return false;
  }

  if(messageHandler_IsAProbe(message_FixedHeader(interestMessage))){
    bool reply_to_probe = false;
    ConnectionTable * ct = forwarder_GetConnectionTable(processor->forwarder);
    const NumberSet * nexthops = fibEntry_GetNexthops(fibEntry);
    unsigned size = (unsigned) numberSet_Length(nexthops);

    for (unsigned i = 0; i < size; i++) {
      unsigned nhop = numberSet_GetItem(nexthops, i);
      Connection *conn =
          (Connection *)connectionTable_FindById(ct, nhop);
      if (!conn)
        continue;
      bool isLocal = connection_IsLocal(conn);
      if(isLocal){
        Connection * replyConn =
                  (Connection *)connectionTable_FindById(ct,
                    message_GetIngressConnectionId(interestMessage));
        connection_HandleProbe(replyConn,
                  (uint8_t *) message_FixedHeader(interestMessage));
        reply_to_probe = true;
        break;
      }
    }
    if(reply_to_probe)
      return false;
  }


  PitEntry *pitEntry = pit_GetPitEntry(processor->pit, interestMessage);
  if (pitEntry == NULL) {
    return false;
  }

  pitEntry_AddFibEntry(pitEntry, fibEntry);

  NumberSet *nexthops = (NumberSet *)fibEntry_GetNexthopsFromForwardingStrategy(
#ifdef WITH_POLICY
      fibEntry, interestMessage, verdict);
#else
      fibEntry, interestMessage);
#endif /* WITH_POLICY */

  // this requires some additional checks. It may happen that some of the output
  // faces selected by the forwarding strategy are not usable. So far all the
  // forwarding strategy return only valid faces (or an empty list)
  for (unsigned i = 0; i < numberSet_Length(nexthops); i++) {
    pitEntry_AddEgressId(pitEntry, numberSet_GetItem(nexthops, i));
  }

  // The function GetPitEntry encreases the ref counter in the pit entry
  // we need to decrease it
  pitEntry_Release(&pitEntry);

  if (messageProcessor_ForwardToNexthops(processor, interestMessage, nexthops) >
      0) {
    numberSet_Release(&nexthops);
    return true;
  } else {
    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(processor->logger, LoggerFacility_Processor,
                 PARCLogLevel_Debug, __func__,
                 "Message %p returned an emtpy next hop set",
                 (void *)interestMessage);
    }
  }

  return false;
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
static void messageProcessor_ReceiveInterest(MessageProcessor *processor,
                                             Message *interestMessage) {
  processor->stats.countInterestsReceived++;

  // (1) Try to aggregate in PIT
#ifdef WITH_POLICY
  PITVerdict verdict = messageProcessor_AggregateInterestInPit(processor, interestMessage);
  switch(verdict) {
    case PITVerdict_Aggregate:
      //done
      return;

    case PITVerdict_Forward:
    case PITVerdict_Retransmit:
      break;
  }
#else
  if (messageProcessor_AggregateInterestInPit(processor, interestMessage)) {
    // done
    return;
  }
#endif /* WITH_POLICY */

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
#ifdef WITH_POLICY
  if (messageProcessor_ForwardViaFib(processor, interestMessage, verdict)) {
#else
  if (messageProcessor_ForwardViaFib(processor, interestMessage)) {
#endif /* WITH_POLICY */
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
static void messageProcessor_ReceiveContentObject(MessageProcessor *processor,
                                                  Message *message) {
  processor->stats.countObjectsReceived++;

  NumberSet *ingressSetUnion = pit_SatisfyInterest(processor->pit, message);

  if (numberSet_Length(ingressSetUnion) == 0) {
    // (1) If it does not match anything in the PIT, drop it
    processor->stats.countDroppedNoReversePath++;

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(processor->logger, LoggerFacility_Processor,
                 PARCLogLevel_Debug, __func__,
                 "Message %p did not match PIT, no reverse path (count %u)",
                 (void *)message, processor->stats.countDroppedNoReversePath);
    }

    //if the packet is a probe we need to analyze it
    if(messageHandler_IsAProbe(message_FixedHeader(message))){
      FibEntry *fibEntry = fib_MatchMessage(processor->fib, message);
      if(fibEntry &&
          fibEntry_GetFwdStrategyType(fibEntry) == HICN_STRATEGY_LOW_LATENCY){
        unsigned connid = message_GetIngressConnectionId(message);
        NumberSet *outFace = numberSet_Create();
        numberSet_Add(outFace, connid);
        fibEntry_ReceiveObjectMessage(fibEntry, outFace, message, 0,
                                      forwarder_GetTicks(processor->forwarder));
        numberSet_Release(&(outFace));
      }
    }

    // we store the packets in the content store enven in the case where there
    // is no match in the PIT table in this way the applications can push the
    // content in the CS of the forwarder. We allow this only for local faces
    bool isLocal = connection_IsLocal(connectionTable_FindById(
        forwarder_GetConnectionTable(processor->forwarder),
        message_GetIngressConnectionId((const Message *)message)));
    if (processor->store_in_cache && isLocal) {
      uint64_t currentTimeTicks = forwarder_GetTicks(processor->forwarder);
      contentStoreInterface_PutContent(processor->contentStore, message,
                                       currentTimeTicks);
      if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                            PARCLogLevel_Debug)) {
        logger_Log(processor->logger, LoggerFacility_Processor,
                   PARCLogLevel_Debug, __func__,
                   "Message %p sotred in the CS anyway", (void *)message);
      }
    }

    messageProcessor_Drop(processor, message);
  } else {
    // (2) Add to Content Store. Store may remove expired content, if necessary,
    // depending on store policy.
    if (processor->store_in_cache) {
      uint64_t currentTimeTicks = forwarder_GetTicks(processor->forwarder);
      contentStoreInterface_PutContent(processor->contentStore, message,
                                       currentTimeTicks);
    }
    // (3) Reverse path forward via PIT entries
    messageProcessor_ForwardToNexthops(processor, message, ingressSetUnion);

  }

  numberSet_Release(&ingressSetUnion);
}

/**
 * @function messageProcessor_ForwardToNexthops
 * @abstract Try to forward to each nexthop listed in the NumberSet
 * @discussion
 *   Will not forward to the ingress connection.
 *
 * @return The number of nexthops tried
 */
static unsigned messageProcessor_ForwardToNexthops(MessageProcessor *processor,
                                                   Message *message,
                                                   const NumberSet *nexthops) {
  unsigned forwardedCopies = 0;

  size_t length = numberSet_Length(nexthops);

  unsigned ingressId = message_GetIngressConnectionId(message);
  uint32_t old_path_label = 0;

  if (message_GetType(message) == MessagePacketType_ContentObject) {
    old_path_label = message_GetPathLabel(message);
  }

  for (size_t i = 0; i < length; i++) {
    unsigned egressId = numberSet_GetItem(nexthops, i);
    if (egressId != ingressId) {
      forwardedCopies++;
      messageProcessor_ForwardToInterfaceId(processor, message, egressId);

      if (message_GetType(message) == MessagePacketType_ContentObject) {
        // everytime we send out a message we need to restore the original path
        // label of the message this is important because we keep a single copy
        // of the message (single pointer) and we modify the path label at each
        // send.
        message_SetPathLabel(message, old_path_label);
      }
    }
  }
  return forwardedCopies;
}

/**
 * caller has checked that the hop limit is ok.  Try to send out the connection.
 */
static void messageProcessor_SendWithGoodHopLimit(MessageProcessor *processor,
                                                  Message *message,
                                                  unsigned interfaceId,
                                                  const Connection *conn) {
  bool success = connection_Send(conn, message);
  if (success) {
    switch (message_GetType(message)) {
      case MessagePacketType_Interest:
        processor->stats.countInterestForwarded++;
        break;

      case MessagePacketType_ContentObject:
        processor->stats.countObjectsForwarded++;
        break;

      default:
        break;
    }

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(
          processor->logger, LoggerFacility_Processor, PARCLogLevel_Debug,
          __func__, "forward message %p to interface %u (int %u, obj %u)",
          (void *)message, interfaceId, processor->stats.countInterestForwarded,
          processor->stats.countObjectsForwarded);
    }
  } else {
    processor->stats.countSendFailures++;

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(processor->logger, LoggerFacility_Processor,
                 PARCLogLevel_Debug, __func__,
                 "forward message %p to interface %u send failure (count %u)",
                 (void *)message, interfaceId,
                 processor->stats.countSendFailures);
    }
    messageProcessor_Drop(processor, message);
  }
}

/*
 *   If the hoplimit is equal to 0, then we may only forward it to local
 * applications.  Otherwise, we may forward it off the system.
 *
 */
static void messageProcessor_ForwardToInterfaceId(MessageProcessor *processor,
                                                  Message *message,
                                                  unsigned interfaceId) {
  ConnectionTable *connectionTable =
      forwarder_GetConnectionTable(processor->forwarder);
  const Connection *conn =
      connectionTable_FindById(connectionTable, interfaceId);

  if (conn != NULL) {
    messageProcessor_SendWithGoodHopLimit(processor, message, interfaceId,
                                          conn);
  } else {
    processor->stats.countDroppedConnectionNotFound++;

    if (logger_IsLoggable(processor->logger, LoggerFacility_Processor,
                          PARCLogLevel_Debug)) {
      logger_Log(processor->logger, LoggerFacility_Processor,
                 PARCLogLevel_Debug, __func__,
                 "forward message %p to interface %u not found (count %u)",
                 (void *)message, interfaceId,
                 processor->stats.countDroppedConnectionNotFound);
    }

    messageProcessor_Drop(processor, message);
  }
}

void messageProcessor_SetCacheStoreFlag(MessageProcessor *processor, bool val) {
  processor->store_in_cache = val;
}

bool messageProcessor_GetCacheStoreFlag(MessageProcessor *processor) {
  return processor->store_in_cache;
}

void messageProcessor_SetCacheServeFlag(MessageProcessor *processor, bool val) {
  processor->serve_from_cache = val;
}

bool messageProcessor_GetCacheServeFlag(MessageProcessor *processor) {
  return processor->serve_from_cache;
}

#ifdef WITH_MAPME

FIB *messageProcessor_getFib(MessageProcessor *processor) {
  return processor->fib;
}

#endif /* WITH_MAPME */
