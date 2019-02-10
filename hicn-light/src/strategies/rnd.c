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

#include <src/config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <parc/assert/parc_Assert.h>

#include <parc/algol/parc_HashMap.h>
#include <parc/algol/parc_Memory.h>

#include <src/strategies/rnd.h>

static void _strategyRnd_ReceiveObject(StrategyImpl *strategy,
                                       const NumberSet *egressId,
                                       const Message *objectMessage, Ticks rtt);
static void _strategyRnd_OnTimeout(StrategyImpl *strategy,
                                   const NumberSet *egressId);
static NumberSet *_strategyRnd_LookupNexthop(StrategyImpl *strategy,
                                             const Message *interestMessage);
static NumberSet *_strategyRnd_ReturnNexthops(StrategyImpl *strategy);
static unsigned _strategyRnd_CountNexthops(StrategyImpl *strategy);
static void _strategyRnd_AddNexthop(StrategyImpl *strategy,
                                    unsigned connectionId);
static void _strategyRnd_RemoveNexthop(StrategyImpl *strategy,
                                       unsigned connectionId);
static void _strategyRnd_ImplDestroy(StrategyImpl **strategyPtr);
static strategy_type _strategyRnd_GetStrategy(StrategyImpl *strategy);

static StrategyImpl _template = {
    .context = NULL,
    .receiveObject = &_strategyRnd_ReceiveObject,
    .onTimeout = &_strategyRnd_OnTimeout,
    .lookupNexthop = &_strategyRnd_LookupNexthop,
    .returnNexthops = &_strategyRnd_ReturnNexthops,
    .countNexthops = &_strategyRnd_CountNexthops,
    .addNexthop = &_strategyRnd_AddNexthop,
    .removeNexthop = &_strategyRnd_RemoveNexthop,
    .destroy = &_strategyRnd_ImplDestroy,
    .getStrategy = &_strategyRnd_GetStrategy,
};

struct strategy_rnd;
typedef struct strategy_rnd StrategyRnd;

struct strategy_rnd {
  NumberSet *nexthops;
};

StrategyImpl *strategyRnd_Create() {
  StrategyRnd *strategy = parcMemory_AllocateAndClear(sizeof(StrategyRnd));
  parcAssertNotNull(strategy, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(StrategyRnd));

  strategy->nexthops = numberSet_Create();
  srand((unsigned int)time(NULL));

  StrategyImpl *impl = parcMemory_AllocateAndClear(sizeof(StrategyImpl));
  parcAssertNotNull(impl, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(StrategyImpl));
  memcpy(impl, &_template, sizeof(StrategyImpl));
  impl->context = strategy;
  return impl;
}

// =======================================================
// Dispatch API

strategy_type _strategyRnd_GetStrategy(StrategyImpl *strategy) {
  return SET_STRATEGY_RANDOM;
}

static int _select_Nexthop(StrategyRnd *strategy) {
  unsigned len = (unsigned)numberSet_Length(strategy->nexthops);
  if (len == 0) {
    return -1;
  }

  int rnd = (rand() % len);
  return numberSet_GetItem(strategy->nexthops, rnd);
}

static void _strategyRnd_ReceiveObject(StrategyImpl *strategy,
                                       const NumberSet *egressId,
                                       const Message *objectMessage,
                                       Ticks rtt) {}

static void _strategyRnd_OnTimeout(StrategyImpl *strategy,
                                   const NumberSet *egressId) {}

static NumberSet *_strategyRnd_LookupNexthop(StrategyImpl *strategy,
                                             const Message *interestMessage) {
  StrategyRnd *srnd = (StrategyRnd *)strategy->context;

  unsigned in_connection = message_GetIngressConnectionId(interestMessage);
  unsigned nexthopSize = (unsigned)numberSet_Length(srnd->nexthops);

  NumberSet *out = numberSet_Create();
  if ((nexthopSize == 0) ||
      ((nexthopSize == 1) &&
       numberSet_Contains(srnd->nexthops, in_connection))) {
    // there are no output faces or the input face is also the only output face.
    // return null to avoid loops
    return out;
  }

  unsigned out_connection;
  do {
    out_connection = _select_Nexthop(srnd);
  } while (out_connection == in_connection);

  if (out_connection == -1) {
    return out;
  }

  numberSet_Add(out, out_connection);
  return out;
}

static NumberSet *_strategyRnd_ReturnNexthops(StrategyImpl *strategy) {
  StrategyRnd *srnd = (StrategyRnd *)strategy->context;
  return srnd->nexthops;
}

unsigned _strategyRnd_CountNexthops(StrategyImpl *strategy) {
  StrategyRnd *srnd = (StrategyRnd *)strategy->context;
  return (unsigned)numberSet_Length(srnd->nexthops);
}

static void _strategyRnd_AddNexthop(StrategyImpl *strategy,
                                    unsigned connectionId) {
  StrategyRnd *srnd = (StrategyRnd *)strategy->context;
  if (!numberSet_Contains(srnd->nexthops, connectionId)) {
    numberSet_Add(srnd->nexthops, connectionId);
  }
}

static void _strategyRnd_RemoveNexthop(StrategyImpl *strategy,
                                       unsigned connectionId) {
  StrategyRnd *srnd = (StrategyRnd *)strategy->context;

  if (numberSet_Contains(srnd->nexthops, connectionId)) {
    numberSet_Remove(srnd->nexthops, connectionId);
  }
}

static void _strategyRnd_ImplDestroy(StrategyImpl **strategyPtr) {
  parcAssertNotNull(strategyPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*strategyPtr,
                    "Parameter must dereference to non-null pointer");

  StrategyImpl *impl = *strategyPtr;
  StrategyRnd *strategy = (StrategyRnd *)impl->context;

  numberSet_Release(&(strategy->nexthops));

  parcMemory_Deallocate((void **)&strategy);
  parcMemory_Deallocate((void **)&impl);
  *strategyPtr = NULL;
}
