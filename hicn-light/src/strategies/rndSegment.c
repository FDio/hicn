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
#include <src/core/nameBitvector.h>
#include <src/strategies/rndSegment.h>

static void _strategyRndSegment_ReceiveObject(StrategyImpl *strategy,
                                              const NumberSet *egressId,
                                              const Message *objectMessage,
                                              Ticks rtt);
static void _strategyRndSegment_OnTimeout(StrategyImpl *strategy,
                                          const NumberSet *egressId);
static NumberSet *_strategyRndSegment_LookupNexthop(
    StrategyImpl *strategy, const Message *interestMessage);
static NumberSet *_strategyRndSegment_ReturnNexthops(StrategyImpl *strategy);
static unsigned _strategyRndSegment_CountNexthops(StrategyImpl *strategy);
static void _strategyRndSegment_AddNexthop(StrategyImpl *strategy,
                                           unsigned connectionId);
static void _strategyRndSegment_RemoveNexthop(StrategyImpl *strategy,
                                              unsigned connectionId);
static void _strategyRndSegment_ImplDestroy(StrategyImpl **strategyPtr);
static strategy_type _strategyRndSegment_GetStrategy(StrategyImpl *strategy);

static StrategyImpl _template = {
    .context = NULL,
    .receiveObject = &_strategyRndSegment_ReceiveObject,
    .onTimeout = &_strategyRndSegment_OnTimeout,
    .lookupNexthop = &_strategyRndSegment_LookupNexthop,
    .returnNexthops = &_strategyRndSegment_ReturnNexthops,
    .countNexthops = &_strategyRndSegment_CountNexthops,
    .addNexthop = &_strategyRndSegment_AddNexthop,
    .removeNexthop = &_strategyRndSegment_RemoveNexthop,
    .destroy = &_strategyRndSegment_ImplDestroy,
    .getStrategy = &_strategyRndSegment_GetStrategy,
};

struct strategy_rnd_segment;
typedef struct strategy_rnd_segment StrategyRndSegment;

struct strategy_rnd_segment {
  NumberSet *nexthops;
  NameBitvector *segmentName;
  int last_used_face;
};

StrategyImpl *strategyRndSegment_Create() {
  StrategyRndSegment *strategy =
      parcMemory_AllocateAndClear(sizeof(StrategyRndSegment));
  parcAssertNotNull(strategy, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(StrategyRndSegment));

  strategy->nexthops = numberSet_Create();
  strategy->segmentName = NULL;
  strategy->last_used_face = 0;
  srand(time(NULL));

  StrategyImpl *impl = parcMemory_AllocateAndClear(sizeof(StrategyImpl));
  parcAssertNotNull(impl, "parcMemory_AllocateAndClear(%zu) returned NULL",
                    sizeof(StrategyImpl));
  memcpy(impl, &_template, sizeof(StrategyImpl));
  impl->context = strategy;

  return impl;
}

// =======================================================
// Dispatch API

strategy_type _strategyRndSegment_GetStrategy(StrategyImpl *strategy) {
  return SET_STRATEGY_RANDOM_PER_DASH_SEGMENT;
}

static int _select_Nexthop(StrategyRndSegment *strategy) {
  unsigned len = numberSet_Length(strategy->nexthops);
  if (len == 0) {
    return -1;
  }

  int rnd = (rand() % len);
  return numberSet_GetItem(strategy->nexthops, rnd);
}

static void _strategyRndSegment_ReceiveObject(StrategyImpl *strategy,
                                              const NumberSet *egressId,
                                              const Message *objectMessage,
                                              Ticks rtt) {}

static void _strategyRndSegment_OnTimeout(StrategyImpl *strategy,
                                          const NumberSet *egressId) {}

static NumberSet *_strategyRndSegment_LookupNexthop(
    StrategyImpl *strategy, const Message *interestMessage) {
  StrategyRndSegment *srnd = (StrategyRndSegment *)strategy->context;

  unsigned in_connection = message_GetIngressConnectionId(interestMessage);
  unsigned nexthopSize = numberSet_Length(srnd->nexthops);

  NumberSet *out = numberSet_Create();
  if ((nexthopSize == 0) ||
      ((nexthopSize == 1) &&
       numberSet_Contains(srnd->nexthops, in_connection))) {
    // there are no output faces or the input face is also the only output face.
    // return null to avoid loops
    return out;
  }

  NameBitvector *interestName =
      name_GetContentName(message_GetName(interestMessage));

  if (srnd->segmentName == NULL) {
    srnd->segmentName = nameBitvector_Copy(interestName);
  } else if (!nameBitvector_Equals(srnd->segmentName, interestName)) {
    nameBitvector_Destroy(&srnd->segmentName);
    srnd->segmentName = nameBitvector_Copy(interestName);
  } else {
    // here we need to check if the output face still exists or if someone erase
    // it
    if (numberSet_Contains(srnd->nexthops, srnd->last_used_face)) {
      // face exists, so keep using it!
      numberSet_Add(out, srnd->last_used_face);
      return out;
    } else {
      // the face does not exists anymore, try to find a new face but keep the
      // name of the dash segment
    }
  }

  int out_connection;
  do {
    out_connection = _select_Nexthop(srnd);
  } while (out_connection == in_connection);

  if (out_connection == -1) {
    return out;
  }

  srnd->last_used_face = out_connection;
  numberSet_Add(out, out_connection);
  return out;
}

static NumberSet *_strategyRndSegment_ReturnNexthops(StrategyImpl *strategy) {
  StrategyRndSegment *srnd = (StrategyRndSegment *)strategy->context;
  return srnd->nexthops;
}

unsigned _strategyRndSegment_CountNexthops(StrategyImpl *strategy) {
  StrategyRndSegment *srnd = (StrategyRndSegment *)strategy->context;
  return numberSet_Length(srnd->nexthops);
}

static void _strategyRndSegment_AddNexthop(StrategyImpl *strategy,
                                           unsigned connectionId) {
  StrategyRndSegment *srnd = (StrategyRndSegment *)strategy->context;
  if (!numberSet_Contains(srnd->nexthops, connectionId)) {
    numberSet_Add(srnd->nexthops, connectionId);
  }
}

static void _strategyRndSegment_RemoveNexthop(StrategyImpl *strategy,
                                              unsigned connectionId) {
  StrategyRndSegment *srnd = (StrategyRndSegment *)strategy->context;

  if (numberSet_Contains(srnd->nexthops, connectionId)) {
    numberSet_Remove(srnd->nexthops, connectionId);
  }
}

static void _strategyRndSegment_ImplDestroy(StrategyImpl **strategyPtr) {
  parcAssertNotNull(strategyPtr, "Parameter must be non-null double pointer");
  parcAssertNotNull(*strategyPtr,
                    "Parameter must dereference to non-null pointer");

  StrategyImpl *impl = *strategyPtr;
  StrategyRndSegment *strategy = (StrategyRndSegment *)impl->context;

  numberSet_Release(&(strategy->nexthops));
  if (strategy->segmentName != NULL) {
    nameBitvector_Destroy(&strategy->segmentName);
  }

  parcMemory_Deallocate((void **)&strategy);
  parcMemory_Deallocate((void **)&impl);
  *strategyPtr = NULL;
}
