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

#include <limits.h>
#include <src/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_Memory.h>
#include <parc/algol/parc_Object.h>
#include <parc/algol/parc_Unsigned.h>

#include <src/strategies/loadBalancerWithPD.h>
#include <src/strategies/nexthopStateWithPD.h>

const unsigned PROBE_FREQUENCY = 1024;

static void _strategyLoadBalancerWithPD_ReceiveObject(
    StrategyImpl *strategy, const NumberSet *egressId,
    const Message *objectMessage, Ticks rtt);
static void _strategyLoadBalancerWithPD_OnTimeout(StrategyImpl *strategy,
                                                  const NumberSet *egressId);
static NumberSet *_strategyLoadBalancerWithPD_LookupNexthop(
    StrategyImpl *strategy, const Message *interestMessage);
static NumberSet *_strategyLoadBalancerWithPD_ReturnNexthops(
    StrategyImpl *strategy);
static unsigned _strategyLoadBalancerWithPD_CountNexthops(
    StrategyImpl *strategy);
static void _strategyLoadBalancerWithPD_AddNexthop(StrategyImpl *strategy,
                                                   unsigned connectionId);
static void _strategyLoadBalancerWithPD_RemoveNexthop(StrategyImpl *strategy,
                                                      unsigned connectionId);
static void _strategyLoadBalancerWithPD_ImplDestroy(StrategyImpl **strategyPtr);
static strategy_type _strategyLoadBalancerWithPD_GetStrategy(
    StrategyImpl *strategy);

static StrategyImpl _template = {
    .context = NULL,
    .receiveObject = &_strategyLoadBalancerWithPD_ReceiveObject,
    .onTimeout = &_strategyLoadBalancerWithPD_OnTimeout,
    .lookupNexthop = &_strategyLoadBalancerWithPD_LookupNexthop,
    .returnNexthops = &_strategyLoadBalancerWithPD_ReturnNexthops,
    .countNexthops = &_strategyLoadBalancerWithPD_CountNexthops,
    .addNexthop = &_strategyLoadBalancerWithPD_AddNexthop,
    .removeNexthop = &_strategyLoadBalancerWithPD_RemoveNexthop,
    .destroy = &_strategyLoadBalancerWithPD_ImplDestroy,
    .getStrategy = &_strategyLoadBalancerWithPD_GetStrategy,
};

struct strategy_load_balancer_with_pd;
typedef struct strategy_load_balancer_with_pd StrategyLoadBalancerWithPD;

struct strategy_load_balancer_with_pd {
  double weights_sum;
  unsigned min_delay;
  // hash map from connectionId to StrategyNexthopState
  PARCHashMap *strategy_state;
  NumberSet *nexthops;
  ConnectionTable *connTable;
  bool toInit;
  unsigned int fwdPackets;
};

StrategyImpl *strategyLoadBalancerWithPD_Create() {
  StrategyLoadBalancerWithPD *strategy =
      parcMemory_AllocateAndClear(sizeof(StrategyLoadBalancerWithPD));
  parcAssertNotNull(strategy, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(StrategyLoadBalancerWithPD));

  strategy->weights_sum = 0.0;
  strategy->min_delay = INT_MAX;
  strategy->strategy_state = parcHashMap_Create();
  strategy->nexthops = numberSet_Create();
  srand(time(NULL));

  StrategyImpl *impl = parcMemory_AllocateAndClear(sizeof(StrategyImpl));
  parcAssertNotNull(impl, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(StrategyImpl));
  memcpy(impl, &_template, sizeof(StrategyImpl));
  impl->context = strategy;
  strategy->connTable = NULL;
  strategy->fwdPackets = 0;
  strategy->toInit = true;

  return impl;
}

void strategyLoadBalancerWithPD_SetConnectionTable(StrategyImpl *strategy,
                                                   ConnectionTable *connTable) {
  StrategyLoadBalancerWithPD *lb =
      (StrategyLoadBalancerWithPD *)strategy->context;
  lb->connTable = connTable;
}

// =======================================================
// Dispatch API

strategy_type _strategyLoadBalancerWithPD_GetStrategy(StrategyImpl *strategy) {
  return SET_STRATEGY_LOADBALANCER_WITH_DELAY;
}

static void _update_Stats(StrategyLoadBalancerWithPD *strategy,
                          StrategyNexthopStateWithPD *state, bool inc,
                          Ticks rtt) {
  const double ALPHA = 0.9;
  double w = strategyNexthopStateWithPD_GetWeight(state);
  strategy->weights_sum -= w;
  w = strategyNexthopStateWithPD_UpdateState(state, inc, strategy->min_delay,
                                             ALPHA);
  strategy->weights_sum += w;
}

static void _sendProbes(StrategyLoadBalancerWithPD *strategy) {
  unsigned size = numberSet_Length(strategy->nexthops);
  for (unsigned i = 0; i < size; i++) {
    unsigned nhop = numberSet_GetItem(strategy->nexthops, i);
    Connection *conn =
        (Connection *)connectionTable_FindById(strategy->connTable, nhop);
    if (conn != NULL) {
      connection_Probe(conn);
      unsigned delay = connection_GetDelay(conn);
      PARCUnsigned *cid = parcUnsigned_Create(nhop);
      StrategyNexthopStateWithPD *elem =
          (StrategyNexthopStateWithPD *)parcHashMap_Get(
              strategy->strategy_state, cid);
      strategyNexthopStateWithPD_SetDelay(elem, delay);
      if (delay < strategy->min_delay && delay != 0) {
        strategy->min_delay = delay;
      }

      parcUnsigned_Release(&cid);
    }
  }
}

static unsigned _select_Nexthop(StrategyLoadBalancerWithPD *strategy) {
  strategy->fwdPackets++;
  if (strategy->toInit || strategy->fwdPackets == PROBE_FREQUENCY) {
    strategy->toInit = false;
    strategy->fwdPackets = 0;
    _sendProbes(strategy);
  }
  double rnd = (double)rand() / (double)RAND_MAX;
  double start_range = 0.0;

  PARCIterator *it = parcHashMap_CreateKeyIterator(strategy->strategy_state);

  unsigned nexthop = 100000;
  while (parcIterator_HasNext(it)) {
    PARCUnsigned *cid = parcIterator_Next(it);
    const StrategyNexthopStateWithPD *elem =
        parcHashMap_Get(strategy->strategy_state, cid);

    double w = strategyNexthopStateWithPD_GetWeight(elem);

    // printf("next = %u .. pi %u avgpi %f w %f avgrtt
    // %f\n",parcUnsigned_GetUnsigned(cid),
    // strategyNexthopStateWithPD_GetPI(elem),
    //        strategyNexthopStateWithPD_GetWeight(elem),
    //        strategyNexthopStateWithPD_GetWeight(elem),
    //        strategyNexthopStateWithPD_GetAvgRTT(elem));

    double prob = w / strategy->weights_sum;
    if ((rnd >= start_range) && (rnd < (start_range + prob))) {
      nexthop = parcUnsigned_GetUnsigned(cid);
      break;
    } else {
      start_range += prob;
    }
  }

  parcIterator_Release(&it);

  // if no face is selected by the algorithm (for example because of a wrong
  // round in the weights) we may always select the last face here. Double check
  // this!
  return nexthop;
}

static void _strategyLoadBalancerWithPD_ReceiveObject(
    StrategyImpl *strategy, const NumberSet *egressId,
    const Message *objectMessage, Ticks rtt) {
  StrategyLoadBalancerWithPD *lb =
      (StrategyLoadBalancerWithPD *)strategy->context;

  for (unsigned i = 0; i < numberSet_Length(egressId); i++) {
    unsigned outId = numberSet_GetItem(egressId, i);
    PARCUnsigned *cid = parcUnsigned_Create(outId);

    const StrategyNexthopStateWithPD *state =
        parcHashMap_Get(lb->strategy_state, cid);
    if (state != NULL) {
      _update_Stats(lb, (StrategyNexthopStateWithPD *)state, false, 0);
    } else {
      // this may happen if we remove a face/route while downloading a file
      // we should ignore this timeout
    }
    parcUnsigned_Release(&cid);
  }
}

static void _strategyLoadBalancerWithPD_OnTimeout(StrategyImpl *strategy,
                                                  const NumberSet *egressId) {
  StrategyLoadBalancerWithPD *lb =
      (StrategyLoadBalancerWithPD *)strategy->context;

  for (unsigned i = 0; i < numberSet_Length(egressId); i++) {
    unsigned outId = numberSet_GetItem(egressId, i);
    PARCUnsigned *cid = parcUnsigned_Create(outId);

    const StrategyNexthopStateWithPD *state =
        parcHashMap_Get(lb->strategy_state, cid);
    if (state != NULL) {
      _update_Stats(lb, (StrategyNexthopStateWithPD *)state, false, 0);
    } else {
      // this may happen if we remove a face/route while downloading a file
      // we should ignore this timeout
    }
    parcUnsigned_Release(&cid);
  }
}

// ATTENTION!! This interface force us to create a NumberSet which need to be
// delited somewhere The specification in the interface requires that this
// function never returns NULL. in case we have no output face we need to return
// an empty NumberSet
static NumberSet *_strategyLoadBalancerWithPD_LookupNexthop(
    StrategyImpl *strategy, const Message *interestMessage) {
  StrategyLoadBalancerWithPD *lb =
      (StrategyLoadBalancerWithPD *)strategy->context;

  unsigned in_connection = message_GetIngressConnectionId(interestMessage);
  PARCUnsigned *in = parcUnsigned_Create(in_connection);

  unsigned mapSize = parcHashMap_Size(lb->strategy_state);
  NumberSet *outList = numberSet_Create();

  if ((mapSize == 0) ||
      ((mapSize == 1) && parcHashMap_Contains(lb->strategy_state, in))) {
    // there are no output faces or the input face is also the only output face.
    // return null to avoid loops
    parcUnsigned_Release(&in);
    return outList;
  }

  unsigned out_connection;
  do {
    out_connection = _select_Nexthop(lb);
  } while (out_connection == in_connection);

  PARCUnsigned *out = parcUnsigned_Create(out_connection);

  const StrategyNexthopStateWithPD *state =
      parcHashMap_Get(lb->strategy_state, out);
  if (state == NULL) {
    // this is an error and should not happen!
    parcTrapNotImplemented(
        "Try to send an interest on a face that does not exists");
  }

  _update_Stats(lb, (StrategyNexthopStateWithPD *)state, true, 0);

  parcUnsigned_Release(&in);
  parcUnsigned_Release(&out);

  numberSet_Add(outList, out_connection);
  return outList;
}

static NumberSet *_strategyLoadBalancerWithPD_ReturnNexthops(
    StrategyImpl *strategy) {
  StrategyLoadBalancerWithPD *lb =
      (StrategyLoadBalancerWithPD *)strategy->context;
  return lb->nexthops;
}

unsigned _strategyLoadBalancerWithPD_CountNexthops(StrategyImpl *strategy) {
  StrategyLoadBalancerWithPD *lb =
      (StrategyLoadBalancerWithPD *)strategy->context;
  return numberSet_Length(lb->nexthops);
}

static void _strategyLoadBalancerWithPD_resetState(StrategyImpl *strategy) {
  StrategyLoadBalancerWithPD *lb =
      (StrategyLoadBalancerWithPD *)strategy->context;
  lb->weights_sum = 0.0;
  lb->min_delay = INT_MAX;
  lb->toInit = true;
  PARCIterator *it = parcHashMap_CreateKeyIterator(lb->strategy_state);

  while (parcIterator_HasNext(it)) {
    PARCUnsigned *cid = parcIterator_Next(it);
    StrategyNexthopStateWithPD *elem =
        (StrategyNexthopStateWithPD *)parcHashMap_Get(lb->strategy_state, cid);

    strategyNexthopStateWithPD_Reset(elem);
    lb->weights_sum += strategyNexthopStateWithPD_GetWeight(elem);
  }

  parcIterator_Release(&it);
}

static void _strategyLoadBalancerWithPD_AddNexthop(StrategyImpl *strategy,
                                                   unsigned connectionId) {
  StrategyNexthopStateWithPD *state = strategyNexthopStateWithPD_Create();

  PARCUnsigned *cid = parcUnsigned_Create(connectionId);

  StrategyLoadBalancerWithPD *lb =
      (StrategyLoadBalancerWithPD *)strategy->context;

  if (!parcHashMap_Contains(lb->strategy_state, cid)) {
    parcHashMap_Put(lb->strategy_state, cid, state);
    numberSet_Add(lb->nexthops, connectionId);
    _strategyLoadBalancerWithPD_resetState(strategy);
  }
}

static void _strategyLoadBalancerWithPD_RemoveNexthop(StrategyImpl *strategy,
                                                      unsigned connectionId) {
  StrategyLoadBalancerWithPD *lb =
      (StrategyLoadBalancerWithPD *)strategy->context;

  PARCUnsigned *cid = parcUnsigned_Create(connectionId);

  if (parcHashMap_Contains(lb->strategy_state, cid)) {
    parcHashMap_Remove(lb->strategy_state, cid);
    numberSet_Remove(lb->nexthops, connectionId);
    _strategyLoadBalancerWithPD_resetState(strategy);
  }

  parcUnsigned_Release(&cid);
}

static void _strategyLoadBalancerWithPD_ImplDestroy(
    StrategyImpl **strategyPtr) {
  parcAssertNotNull(strategyPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*strategyPtr,
                    "Parameter must dereference to non-null pointer");

  StrategyImpl *impl = *strategyPtr;
  StrategyLoadBalancerWithPD *strategy =
      (StrategyLoadBalancerWithPD *)impl->context;

  parcHashMap_Release(&(strategy->strategy_state));
  numberSet_Release(&(strategy->nexthops));

  parcMemory_Deallocate((void **)&strategy);
  parcMemory_Deallocate((void **)&impl);
  *strategyPtr = NULL;
}
