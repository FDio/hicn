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

#include <hicn/core/numberSet.h>
#include <hicn/processor/fibEntry.h>

#include <hicn/core/nameBitvector.h>

#include <hicn/strategies/loadBalancer.h>
#include <hicn/strategies/lowLatency.h>
#include <hicn/strategies/rnd.h>
#include <hicn/strategies/strategyImpl.h>
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

#define ALPHA 0.5

#endif /* WITH_POLICY */

struct fib_entry {
  Name *name;
  unsigned refcount;
  StrategyImpl *fwdStrategy;
#ifdef WITH_POLICY
  NumberSet *nexthops;
  const Forwarder * forwarder;
  policy_t policy;
  policy_counters_t policy_counters;
//  NumberSet *available_nexthops;
#ifdef WITH_MAPME
  /* In case of no multipath, this stores the previous decision taken by policy */
#endif /* WITH_MAPME */
#endif /* WITH_POLICY */
#ifdef WITH_MAPME
  NumberSet * previous_nexthops;
  void *userData;
  void (*userDataRelease)(void **userData);
#endif /* WITH_MAPME */
};

#ifdef WITH_POLICY
FibEntry *fibEntry_Create(Name *name, hicn_strategy_t fwdStrategy, const Forwarder * forwarder) {
#else
FibEntry *fibEntry_Create(Name *name, hicn_strategy_t fwdStrategy) {
#endif /* WITH_POLICY */
  FibEntry *fibEntry = parcMemory_AllocateAndClear(sizeof(FibEntry));
  parcAssertNotNull(fibEntry, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(FibEntry));
  fibEntry->name = name_Acquire(name);

  switch (fwdStrategy) {
    case HICN_STRATEGY_LOAD_BALANCER:
      fibEntry->fwdStrategy = strategyLoadBalancer_Create();
      break;

    case HICN_STRATEGY_RANDOM:
      fibEntry->fwdStrategy = strategyRnd_Create();

    case HICN_STRATEGY_LOW_LATENCY:
      fibEntry->fwdStrategy = strategyLowLatency_Create();
      break;

    default:
      // LB is the default strategy
      fwdStrategy = HICN_STRATEGY_LOAD_BALANCER;
      fibEntry->fwdStrategy = strategyLoadBalancer_Create();
      break;
  }

  fibEntry->refcount = 1;

#ifdef WITH_MAPME
  fibEntry->userData = NULL;
  fibEntry->userDataRelease = NULL;
#endif /* WITH_MAPME */

#ifdef WITH_POLICY
  fibEntry->nexthops = numberSet_Create();
  fibEntry->forwarder = forwarder;
  fibEntry->policy = POLICY_NONE;
  fibEntry->policy_counters = POLICY_COUNTERS_NONE;
#endif /* WITH_POLICY */

  if(fwdStrategy == HICN_STRATEGY_LOW_LATENCY){
    strategyLowLatency_SetStrategy(fibEntry->fwdStrategy,
                                     fibEntry->forwarder, fibEntry,
                                     0, NULL);
  }
  return fibEntry;
}

FibEntry *fibEntry_Acquire(const FibEntry *fibEntry) {
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
  FibEntry *copy = (FibEntry *)fibEntry;
  copy->refcount++;
  return copy;
}

void fibEntry_Release(FibEntry **fibEntryPtr) {
  FibEntry *fibEntry = *fibEntryPtr;
  parcAssertTrue(fibEntry->refcount > 0, "Illegal state: refcount is 0");
  fibEntry->refcount--;
  if (fibEntry->refcount == 0) {
    name_Release(&fibEntry->name);
    fibEntry->fwdStrategy->destroy(&(fibEntry->fwdStrategy));
#ifdef WITH_MAPME
    if (fibEntry->userData) {
      fibEntry->userDataRelease(&fibEntry->userData);
    }
#endif /* WITH_MAPME */
#ifdef WITH_POLICY
  numberSet_Release(&fibEntry->nexthops);
#endif /* WITH_POLICY */
    parcMemory_Deallocate((void **)&fibEntry);
  }
  *fibEntryPtr = NULL;
}

void fibEntry_SetStrategy(FibEntry *fibEntry, hicn_strategy_t strategy,
                          unsigned related_prefixes_len,
                          Name **related_prefixes) {
  StrategyImpl *fwdStrategyImpl;

  switch (strategy) {
    case HICN_STRATEGY_LOAD_BALANCER:
      fwdStrategyImpl = strategyLoadBalancer_Create();
      break;

    case HICN_STRATEGY_RANDOM:
      fwdStrategyImpl = strategyRnd_Create();
      break;

    case HICN_STRATEGY_LOW_LATENCY:
      fwdStrategyImpl = strategyLowLatency_Create();
      break;

    default:
      // LB is the default strategy
      strategy = HICN_STRATEGY_LOAD_BALANCER;
      fwdStrategyImpl = strategyLoadBalancer_Create();
      break;
    }

  if(strategy == HICN_STRATEGY_LOW_LATENCY){
    strategyLowLatency_SetStrategy(fwdStrategyImpl,
                       fibEntry->forwarder, fibEntry,
                       related_prefixes_len, related_prefixes);
  }

  const NumberSet *nexthops = fibEntry_GetNexthops(fibEntry);
  unsigned size = (unsigned)fibEntry_NexthopCount(fibEntry);
  for (unsigned i = 0; i < size; i++) {
    fwdStrategyImpl->addNexthop(fwdStrategyImpl,
                                numberSet_GetItem(nexthops, i));
  }
  fibEntry->fwdStrategy->destroy(&(fibEntry->fwdStrategy));
  fibEntry->fwdStrategy = fwdStrategyImpl;
}

#ifdef WITH_POLICY

/*
 * Update available next hops following policy update.
 */
NumberSet *
fibEntry_GetAvailableNextHops(const FibEntry *fibEntry, unsigned in_connection) {
  ConnectionTable * table = forwarder_GetConnectionTable(fibEntry->forwarder);
  NumberSet * nexthops;
  bool dealloc_nexthops = false;
  policy_t policy = fibEntry_GetPolicy(fibEntry);

  /* Reset available next hops and start filtering */
  NumberSet * available_nexthops = numberSet_Create();

  /*
   * Give absolute preference to local faces, with no policy, unless
   * in_connection == ~0, which means we are searching faces on which to
   * advertise our prefix
   */
  if (in_connection == ~0) {
    /* We might advertise among all available up connections */
    nexthops = numberSet_Create();
    dealloc_nexthops = true;

    ConnectionList * list = connectionTable_GetEntries(table);
    for (size_t i = 0; i < connectionList_Length(list); i++) {
      Connection *conn = connectionList_Get(list, i);
      if (connection_IsLocal(conn))
        continue;
      if (connection_GetAdminState(conn) == CONNECTION_STATE_DOWN)
        continue;
      if (connection_GetState(conn) == CONNECTION_STATE_DOWN)
        continue;
      numberSet_Add(nexthops, connection_GetConnectionId(conn));
    }
    connectionList_Destroy(&list);
  } else {
    nexthops = (NumberSet*)fibEntry_GetNexthops(fibEntry);
    for (size_t k = 0; k < numberSet_Length(nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(nexthops, k);
      /* Filtering out ingress face */
      if (conn_id == in_connection)
        continue;
      /* Filtering out DOWN faces */
      const Connection *  conn = connectionTable_FindById(table, conn_id);
      if (!conn)
        continue;
      if (connection_GetAdminState(conn) == CONNECTION_STATE_DOWN)
        continue;
      if (connection_GetState(conn) == CONNECTION_STATE_DOWN)
        continue;
      if (!connection_IsLocal(conn))
        continue;
      numberSet_Add(available_nexthops, conn_id);
    }

    /* Terminate selection if there are any local face available */
    if (numberSet_Length(available_nexthops) > 0){
      if(dealloc_nexthops){
        numberSet_Release(&nexthops);
      }
      /* No filtering as all local faces are considered equivalent */
      return available_nexthops;
    }
  }

  for (size_t k = 0; k < numberSet_Length(nexthops); k++) {
    unsigned conn_id = numberSet_GetItem(nexthops, k);
    const Connection * conn;

    /* Filtering out ingress face */
    if (conn_id == in_connection)
      continue;

    /* Filtering out DOWN faces */
    conn = connectionTable_FindById(table, conn_id);
    if (!conn)
      continue;
    if (connection_GetAdminState(conn) == CONNECTION_STATE_DOWN)
      continue;
    if (connection_GetState(conn) == CONNECTION_STATE_DOWN)
      continue;

    /* Policy filtering : next hops */
    if ((policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_REQUIRE) &&
        (!connection_HasTag(conn, POLICY_TAG_WIRED)))
      continue;
    if ((policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_PROHIBIT) &&
        (connection_HasTag(conn, POLICY_TAG_WIRED)))
      continue;
    if ((policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_REQUIRE) &&
        (!connection_HasTag(conn, POLICY_TAG_WIFI)))
      continue;
    if ((policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_PROHIBIT) &&
        (connection_HasTag(conn, POLICY_TAG_WIFI)))
      continue;
    if ((policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_REQUIRE) &&
        (!connection_HasTag(conn, POLICY_TAG_CELLULAR)))
      continue;
    if ((policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_PROHIBIT) &&
        (connection_HasTag(conn, POLICY_TAG_CELLULAR)))
      continue;
    if ((policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE) &&
        (!connection_HasTag(conn, POLICY_TAG_TRUSTED)))
      continue;
    if ((policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_PROHIBIT) &&
        (connection_HasTag(conn, POLICY_TAG_TRUSTED)))
      continue;

    numberSet_Add(available_nexthops, conn_id);
  }

  if(dealloc_nexthops)
    numberSet_Release(&nexthops);

  if (numberSet_Length(available_nexthops) == 0)
    return available_nexthops;

  /* We have at least one matching next hop, implement heuristic */

  /*
   * As VPN connections might trigger duplicate uses of one interface, we start
   * by filtering out interfaces based on trust status.
   */
  NumberSet * filtered_nexthops = numberSet_Create();
  if ((policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_REQUIRE) ||
      (policy.tags[POLICY_TAG_TRUSTED].state == POLICY_STATE_PREFER)) {
    /* Try to filter out NON TRUSTED faces */
    for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(available_nexthops, k);
      const Connection * conn = connectionTable_FindById(table, conn_id);
      if (!connection_HasTag(conn, POLICY_TAG_TRUSTED))
          continue;
      numberSet_Add(filtered_nexthops, conn_id);
    }
  } else {
      /* Try to filter out TRUSTED faces */
    for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(available_nexthops, k);
      const Connection * conn = connectionTable_FindById(table, conn_id);
      if (connection_HasTag(conn, POLICY_TAG_TRUSTED))
          continue;
      numberSet_Add(filtered_nexthops, conn_id);
    }
  }
  if (numberSet_Length(filtered_nexthops) > 0) {
    numberSet_Release(&available_nexthops);
    available_nexthops = numberSet_Create();
    numberSet_AddSet(available_nexthops, filtered_nexthops);
  }
  numberSet_Release(&filtered_nexthops);

  /* Other preferences */
  if (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_AVOID) {
    filtered_nexthops = numberSet_Create();
    for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(available_nexthops, k);
      const Connection * conn = connectionTable_FindById(table, conn_id);
      if (connection_HasTag(conn, POLICY_TAG_WIRED))
          continue;
      numberSet_Add(filtered_nexthops, conn_id);
    }
    if (numberSet_Length(filtered_nexthops) > 0) {
        numberSet_Release(&available_nexthops);
        available_nexthops = numberSet_Create();
        numberSet_AddSet(available_nexthops, filtered_nexthops);
    }
    numberSet_Release(&filtered_nexthops);
  }
  if (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_AVOID) {
    filtered_nexthops = numberSet_Create();
    for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(available_nexthops, k);
      const Connection * conn = connectionTable_FindById(table, conn_id);
      if (connection_HasTag(conn, POLICY_TAG_WIFI))
          continue;
      numberSet_Add(filtered_nexthops, conn_id);
    }
    if (numberSet_Length(filtered_nexthops) > 0) {
        numberSet_Release(&available_nexthops);
        available_nexthops = numberSet_Create();
        numberSet_AddSet(available_nexthops, filtered_nexthops);
    }
    numberSet_Release(&filtered_nexthops);
  }
  if (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_AVOID) {
    filtered_nexthops = numberSet_Create();
    for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(available_nexthops, k);
      const Connection * conn = connectionTable_FindById(table, conn_id);
      if (connection_HasTag(conn, POLICY_TAG_CELLULAR))
          continue;
      numberSet_Add(filtered_nexthops, conn_id);
    }
    if (numberSet_Length(filtered_nexthops) > 0) {
        numberSet_Release(&available_nexthops);
        available_nexthops = numberSet_Create();
        numberSet_AddSet(available_nexthops, filtered_nexthops);
    }
    numberSet_Release(&filtered_nexthops);
  }

  if (policy.tags[POLICY_TAG_WIRED].state == POLICY_STATE_PREFER) {
    filtered_nexthops = numberSet_Create();
    for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(available_nexthops, k);
      const Connection * conn = connectionTable_FindById(table, conn_id);
      if (!connection_HasTag(conn, POLICY_TAG_WIRED))
          continue;
      numberSet_Add(filtered_nexthops, conn_id);
    }
    if (numberSet_Length(filtered_nexthops) > 0) {
        numberSet_Release(&available_nexthops);
        available_nexthops = numberSet_Create();
        numberSet_AddSet(available_nexthops, filtered_nexthops);
    }
    numberSet_Release(&filtered_nexthops);
  }
  if (policy.tags[POLICY_TAG_WIFI].state == POLICY_STATE_PREFER) {
    filtered_nexthops = numberSet_Create();
    for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(available_nexthops, k);
      const Connection * conn = connectionTable_FindById(table, conn_id);
      if (!connection_HasTag(conn, POLICY_TAG_WIFI))
          continue;
      numberSet_Add(filtered_nexthops, conn_id);
    }
    if (numberSet_Length(filtered_nexthops) > 0) {
        numberSet_Release(&available_nexthops);
        available_nexthops = numberSet_Create();
        numberSet_AddSet(available_nexthops, filtered_nexthops);
    }
    numberSet_Release(&filtered_nexthops);
  }
  if (policy.tags[POLICY_TAG_CELLULAR].state == POLICY_STATE_PREFER) {
    filtered_nexthops = numberSet_Create();
    for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(available_nexthops, k);
      const Connection * conn = connectionTable_FindById(table, conn_id);
      if (!connection_HasTag(conn, POLICY_TAG_CELLULAR))
          continue;
      numberSet_Add(filtered_nexthops, conn_id);
    }
    if (numberSet_Length(filtered_nexthops) > 0) {
        numberSet_Release(&available_nexthops);
        available_nexthops = numberSet_Create();
        numberSet_AddSet(available_nexthops, filtered_nexthops);
    }
    numberSet_Release(&filtered_nexthops);
  }

  /* Priority */
  NumberSet * priority_nexthops = numberSet_Create();

  uint32_t max_priority = 0;
  for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
    unsigned conn_id = numberSet_GetItem(available_nexthops, k);
    const Connection * conn = connectionTable_FindById(table, conn_id);
    uint32_t priority = connection_GetPriority(conn);
    if (priority < max_priority) {
        continue;
    } else if (priority == max_priority) {
      numberSet_Add(priority_nexthops, conn_id);
    } else { /* priority > max_priority */
      numberSet_Release(&priority_nexthops);
      priority_nexthops = numberSet_Create();
      numberSet_Add(priority_nexthops, conn_id);
      max_priority = priority;
    }
  }

  numberSet_Release(&available_nexthops);

  return priority_nexthops;
}

policy_t fibEntry_GetPolicy(const FibEntry *fibEntry) {
  return fibEntry->policy;
}

void fibEntry_SetPolicy(FibEntry *fibEntry, policy_t policy) {
  fibEntry->policy = policy;
  mapme_reconsiderFibEntry(forwarder_getMapmeInstance(fibEntry->forwarder), fibEntry);
}

NumberSet *
fibEntry_GetPreviousNextHops(const FibEntry *fibEntry)
{
    return fibEntry->previous_nexthops;
}
#endif /* WITH_POLICY */

void
fibEntry_SetPreviousNextHops(FibEntry *fibEntry, const NumberSet * nexthops)
{
    if (fibEntry->previous_nexthops)
        numberSet_Release(&fibEntry->previous_nexthops);
    fibEntry->previous_nexthops = numberSet_Create();
    numberSet_AddSet(fibEntry->previous_nexthops, nexthops);
}


void fibEntry_AddNexthop(FibEntry *fibEntry, unsigned connectionId) {
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
#ifdef WITH_POLICY
  if (!numberSet_Contains(fibEntry->nexthops, connectionId)) {
    numberSet_Add(fibEntry->nexthops, connectionId);
  }
#endif /* WITH_POLICY */
  fibEntry->fwdStrategy->addNexthop(fibEntry->fwdStrategy, connectionId);
}

void fibEntry_RemoveNexthopByConnectionId(FibEntry *fibEntry,
                                          unsigned connectionId) {
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
#ifdef WITH_POLICY
  if (numberSet_Contains(fibEntry->nexthops, connectionId)) {
    numberSet_Remove(fibEntry->nexthops, connectionId);
  }
#endif /* WITH_POLICY */
  fibEntry->fwdStrategy->removeNexthop(fibEntry->fwdStrategy, connectionId);
}

size_t fibEntry_NexthopCount(const FibEntry *fibEntry) {
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
#ifdef WITH_POLICY
  return numberSet_Length(fibEntry->nexthops);
#else
  return fibEntry->fwdStrategy->countNexthops(fibEntry->fwdStrategy);
#endif /* WITH_POLICY */
}

const NumberSet *fibEntry_GetNexthops(const FibEntry *fibEntry) {
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
#ifdef WITH_POLICY
  return fibEntry->nexthops;
#else
  return fibEntry->fwdStrategy->returnNexthops(fibEntry->fwdStrategy);
#endif /* WITH_POLICY */
}

const NumberSet *fibEntry_GetNexthopsFromForwardingStrategy(
#ifdef WITH_POLICY
    FibEntry *fibEntry, const Message *interestMessage, bool is_retransmission) {
#else
    const FibEntry *fibEntry, const Message *interestMessage) {
#endif /* WITH_POLICY */
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
#ifdef WITH_POLICY
  ConnectionTable * table = forwarder_GetConnectionTable(fibEntry->forwarder);
  unsigned in_connection = message_GetIngressConnectionId(interestMessage);

  policy_t policy = fibEntry_GetPolicy(fibEntry);

  NumberSet * out;

  /* Filtering */
  NumberSet * available_nexthops = fibEntry_GetAvailableNextHops(fibEntry, in_connection);
  if (numberSet_Length(available_nexthops) == 0) {
    numberSet_Release(&available_nexthops);
    out = numberSet_Create();
    return out;
  }

  /*
   * Update statistics about loss rates. We only detect losses upon
   * retransmissions, and assume for the computation that the candidate set of
   * output faces is the same as previously (i.e. does not take into account
   * event such as face up/down, policy update, etc. Otherwise we would need to
   * know what was the previous choice !
   */
  if (is_retransmission) {
    for (size_t k = 0; k < numberSet_Length(available_nexthops); k++) {
      unsigned conn_id = numberSet_GetItem(available_nexthops, k);
      const Connection * conn = connectionTable_FindById(table, conn_id);

      if (connection_HasTag(conn, POLICY_TAG_WIRED))
        fibEntry->policy_counters.wired.num_losses++;
      if (connection_HasTag(conn, POLICY_TAG_WIFI))
        fibEntry->policy_counters.wifi.num_losses++;
      if (connection_HasTag(conn, POLICY_TAG_CELLULAR))
        fibEntry->policy_counters.cellular.num_losses++;
      fibEntry->policy_counters.all.num_losses++;
    }
  }

  /*
   * NOTE: We might want to call a forwarding strategy even with no nexthop to
   * take a fallback decision.
   */
  if (numberSet_Length(available_nexthops) == 0) {
    out = numberSet_Create();
  } else {
    /* Multipath */
    if ((policy.tags[POLICY_TAG_MULTIPATH].state != POLICY_STATE_PROHIBIT) &&
        (policy.tags[POLICY_TAG_MULTIPATH].state != POLICY_STATE_AVOID)) {
      out = fibEntry->fwdStrategy->lookupNexthop(fibEntry->fwdStrategy, available_nexthops,
          interestMessage);
    } else {
      unsigned nexthop = numberSet_GetItem(available_nexthops, 0);
      out = numberSet_Create();
      numberSet_Add(out, nexthop);
    }
  }

  numberSet_Release(&available_nexthops);

  return out;
#else
  return fibEntry->fwdStrategy->lookupNexthop(fibEntry->fwdStrategy,
          interestMessage);
#endif /* WITH_POLICY */
}

#ifdef WITH_POLICY
void fibEntry_ReceiveObjectMessage(FibEntry *fibEntry,
#else
void fibEntry_ReceiveObjectMessage(const FibEntry *fibEntry,
#endif /* WITH_POLICY */
                                   const NumberSet *egressId,
                                   const Message *objectMessage,
                                   Ticks pitEntryCreation,
                                   Ticks objReception) {
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");

#ifdef WITH_POLICY
  ConnectionTable * table = forwarder_GetConnectionTable(fibEntry->forwarder);

  /* Update statistic counters : */

  size_t msg_size = message_Length(objectMessage);
  Ticks rtt = objReception - pitEntryCreation;

  for (unsigned i = 0; i < numberSet_Length(egressId); i++) {
    unsigned conn_id = numberSet_GetItem(egressId, i);
    const Connection * conn = connectionTable_FindById(table, conn_id);
    if (!conn)
      continue;
    if (connection_HasTag(conn, POLICY_TAG_WIRED)) {
      fibEntry->policy_counters.wired.num_packets++;
      fibEntry->policy_counters.wired.num_bytes += msg_size;
      fibEntry->policy.stats.wired.latency = \
                      ALPHA       * fibEntry->policy.stats.wired.latency + \
                      (1 - ALPHA) * (double)rtt;
      fibEntry->policy_counters.wired.latency_idle = 0;
    }
    if (connection_HasTag(conn, POLICY_TAG_WIFI)) {
      fibEntry->policy_counters.wifi.num_packets++;
      fibEntry->policy_counters.wifi.num_bytes += msg_size;
      fibEntry->policy.stats.wifi.latency = \
                      ALPHA       * fibEntry->policy.stats.wifi.latency + \
                      (1 - ALPHA) * (double)rtt;
      fibEntry->policy_counters.wifi.latency_idle = 0;

    }
    if (connection_HasTag(conn, POLICY_TAG_CELLULAR)) {
      fibEntry->policy_counters.cellular.num_packets++;
      fibEntry->policy_counters.cellular.num_bytes += msg_size;
      fibEntry->policy.stats.cellular.latency = \
                      ALPHA       * fibEntry->policy.stats.cellular.latency + \
                      (1 - ALPHA) * (double)rtt;
      fibEntry->policy_counters.cellular.latency_idle = 0;
    }
  }

  fibEntry->policy.stats.all.latency = \
                    ALPHA       * fibEntry->policy.stats.all.latency + \
                    (1 - ALPHA) * (double)rtt;
  fibEntry->policy_counters.all.latency_idle = 0;

  fibEntry->policy_counters.all.num_packets++;
  fibEntry->policy_counters.all.num_bytes += msg_size;

#endif /* WITH_POLICY */

  fibEntry->fwdStrategy->receiveObject(fibEntry->fwdStrategy, egressId,
                                       objectMessage, pitEntryCreation, objReception);
}

#ifdef WITH_POLICY
void fibEntry_OnTimeout(FibEntry *fibEntry, const NumberSet *egressId) {
#else
void fibEntry_OnTimeout(const FibEntry *fibEntry, const NumberSet *egressId) {
#endif /* WITH_POLICY */
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");

#ifdef WITH_POLICY

  ConnectionTable * table = forwarder_GetConnectionTable(fibEntry->forwarder);

  for (unsigned i = 0; i < numberSet_Length(egressId); i++) {
    unsigned conn_id = numberSet_GetItem(egressId, i);
    const Connection * conn = connectionTable_FindById(table, conn_id);
    if (!conn)
      continue;
    if (connection_HasTag(conn, POLICY_TAG_WIRED)) {
      fibEntry->policy_counters.wired.num_losses++;
    }
    if (connection_HasTag(conn, POLICY_TAG_WIFI)) {
      fibEntry->policy_counters.wifi.num_losses++;
    }
    if (connection_HasTag(conn, POLICY_TAG_CELLULAR)) {
      fibEntry->policy_counters.cellular.num_losses++;
    }
  }

  fibEntry->policy_counters.all.num_losses++;

#endif /* WITH_POLICY */

  fibEntry->fwdStrategy->onTimeout(fibEntry->fwdStrategy, egressId);
}

#ifdef WITH_POLICY
void fibEntry_UpdateStats(FibEntry *fibEntry, uint64_t now) {
  double throughput;
  double loss_rate;

  if (now == fibEntry->policy_counters.last_update)
      return ;

  /* WIRED */

  /*  a) throughput */
  if (fibEntry->policy_counters.wired.num_bytes > 0) {
    throughput = fibEntry->policy_counters.wired.num_bytes / \
          (now - fibEntry->policy_counters.last_update) ;
    throughput = throughput * 8 / 1024;
    if (throughput < 0)
        throughput = 0;
  } else {
    throughput = 0;
  }
  fibEntry->policy.stats.wired.throughput = \
        ALPHA     * fibEntry->policy.stats.wired.throughput + \
        (1-ALPHA) * throughput;

  /* b) loss rate */
  if ((fibEntry->policy_counters.wired.num_losses > 0) && \
          (fibEntry->policy_counters.wired.num_packets > 0)){
      loss_rate = fibEntry->policy_counters.wired.num_losses / \
            fibEntry->policy_counters.wired.num_packets;
      loss_rate *= 100;
  } else {
      loss_rate = 0;
  }
  fibEntry->policy.stats.wired.loss_rate = \
        ALPHA     * fibEntry->policy.stats.wired.loss_rate + \
        (1-ALPHA) * loss_rate;

  /* Latency */
  fibEntry->policy_counters.wired.latency_idle++;
  if (fibEntry->policy_counters.wired.latency_idle > 1)
      fibEntry->policy.stats.wired.latency = 0;
  fibEntry->policy_counters.wifi.latency_idle++;
  if (fibEntry->policy_counters.wifi.latency_idle > 1)
      fibEntry->policy.stats.wifi.latency = 0;
  fibEntry->policy_counters.cellular.latency_idle++;
  if (fibEntry->policy_counters.cellular.latency_idle > 1)
      fibEntry->policy.stats.cellular.latency = 0;
  fibEntry->policy_counters.all.latency_idle++;
  if (fibEntry->policy_counters.all.latency_idle > 1)
      fibEntry->policy.stats.all.latency = 0;

  fibEntry->policy_counters.wired.num_bytes = 0;
  fibEntry->policy_counters.wired.num_losses = 0;
  fibEntry->policy_counters.wired.num_packets = 0;

  /* WIFI */

  /*  a) throughput */
  if (fibEntry->policy_counters.wifi.num_bytes > 0) {
    throughput = fibEntry->policy_counters.wifi.num_bytes / \
          (now - fibEntry->policy_counters.last_update);
    throughput = throughput * 8 / 1024;
    if (throughput < 0)
        throughput = 0;
  } else {
    throughput = 0;
  }
  fibEntry->policy.stats.wifi.throughput = \
        ALPHA     * fibEntry->policy.stats.wifi.throughput + \
        (1-ALPHA) * throughput;

  /* b) loss rate */
  if ((fibEntry->policy_counters.wifi.num_losses > 0) && \
          (fibEntry->policy_counters.wifi.num_packets > 0)) {
    loss_rate = fibEntry->policy_counters.wifi.num_losses / \
          fibEntry->policy_counters.wifi.num_packets;
      loss_rate *= 100;
  } else {
      loss_rate = 0;
  }
  fibEntry->policy.stats.wifi.loss_rate = \
        ALPHA     * fibEntry->policy.stats.wifi.loss_rate + \
        (1-ALPHA) * loss_rate;

  fibEntry->policy_counters.wifi.num_bytes = 0;
  fibEntry->policy_counters.wifi.num_losses = 0;
  fibEntry->policy_counters.wifi.num_packets = 0;

  /* CELLULAR */

  /*  a) throughput */
  if (fibEntry->policy_counters.cellular.num_bytes > 0) {
    throughput = fibEntry->policy_counters.cellular.num_bytes / \
          (now - fibEntry->policy_counters.last_update) ;
    throughput = throughput * 8 / 1024;
    if (throughput < 0)
        throughput = 0;
  } else {
    throughput = 0;
  }
  fibEntry->policy.stats.cellular.throughput = \
        ALPHA     * fibEntry->policy.stats.cellular.throughput + \
        (1-ALPHA) * throughput;

  /* b) loss rate */
  if ((fibEntry->policy_counters.cellular.num_losses > 0) && \
          (fibEntry->policy_counters.cellular.num_packets > 0)) {
    loss_rate = fibEntry->policy_counters.cellular.num_losses / \
          fibEntry->policy_counters.cellular.num_packets;
      loss_rate *= 100;
  } else {
      loss_rate = 0;
  }
  fibEntry->policy.stats.cellular.loss_rate = \
        ALPHA     * fibEntry->policy.stats.cellular.loss_rate + \
        (1-ALPHA) * loss_rate;

  fibEntry->policy_counters.cellular.num_bytes = 0;
  fibEntry->policy_counters.cellular.num_losses = 0;
  fibEntry->policy_counters.cellular.num_packets = 0;

  /* ALL */

  /*  a) throughput */
  if (fibEntry->policy_counters.all.num_bytes > 0) {
    throughput = fibEntry->policy_counters.all.num_bytes / \
          (now - fibEntry->policy_counters.last_update);
    throughput = throughput * 8 / 1024;
    if (throughput < 0)
        throughput = 0;
  } else {
    throughput = 0;
  }
  fibEntry->policy.stats.all.throughput = \
        ALPHA     * fibEntry->policy.stats.all.throughput + \
        (1-ALPHA) * throughput;

  /* b) loss rate */
  if ((fibEntry->policy_counters.all.num_losses > 0) && \
          (fibEntry->policy_counters.all.num_packets > 0)) {
    loss_rate = fibEntry->policy_counters.all.num_losses / \
          fibEntry->policy_counters.all.num_packets;
      loss_rate *= 100;
  } else {
      loss_rate = 0;
  }
  fibEntry->policy.stats.all.loss_rate = \
        ALPHA     * fibEntry->policy.stats.all.loss_rate + \
        (1-ALPHA) * loss_rate;

  fibEntry->policy_counters.all.num_bytes = 0;
  fibEntry->policy_counters.all.num_losses = 0;
  fibEntry->policy_counters.all.num_packets = 0;

  fibEntry->policy_counters.last_update = now;
}
#endif /* WITH_POLICY */

Name *fibEntry_GetPrefix(const FibEntry *fibEntry) {
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
  return fibEntry->name;
  // return metisName_Acquire(fibEntry->name);
}

hicn_strategy_t fibEntry_GetFwdStrategyType(const FibEntry *fibEntry) {
  return fibEntry->fwdStrategy->getStrategy(fibEntry->fwdStrategy);
}

StrategyImpl *fibEntry_GetFwdStrategy(const FibEntry *fibEntry) {
  return fibEntry->fwdStrategy;
}

#ifdef WITH_MAPME

void *fibEntry_getUserData(const FibEntry *fibEntry) {
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
  return fibEntry->userData;
}

void fibEntry_setUserData(FibEntry *fibEntry, const void *userData,
                          void (*userDataRelease)(void **)) {
  parcAssertNotNull(fibEntry, "Parameter fibEntry must be non-null");
  fibEntry->userData = (void *)userData;
  fibEntry->userDataRelease = userDataRelease;
}

#endif /* WITH_MAPME */
