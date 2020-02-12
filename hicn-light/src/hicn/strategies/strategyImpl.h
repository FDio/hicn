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
 * @file strategyImpl.h
 * @brief Defines the function structure for a Strategy implementation
 *
 * <#Detailed Description#>
 *
 */

/**
 * A dispatch structure for a concrete implementation of a forwarding strategy.
 */

#ifndef strategyImpl_h
#define strategyImpl_h

#include <hicn/core/message.h>
#include <hicn/core/numberSet.h>

struct strategy_impl;
typedef struct strategy_impl StrategyImpl;

/**
 * @typedef StrategyImpl
 * @abstract Forwarding strategy implementation
 * @constant receiveObject is called when we receive an object and have a
 * measured round trip time.  This allows a strategy to update its performance
 * data.
 * @constant lookupNexthop Find the set of nexthops to use for the Interest.
 *           May be empty, should not be NULL.  Must be destroyed.
 * @constant addNexthop Add a nexthop to the list of available nexthops with a
 * routing protocol-specific cost.
 * @constant destroy cleans up the strategy, freeing all memory and state.  A
 * strategy is reference counted, so the final destruction only happens after
 * the last reference is released.
 * @discussion <#Discussion#>
 */
struct strategy_impl {
  void *context;
  void (*receiveObject)(StrategyImpl *strategy, const NumberSet *egressId,
                        const Message *objectMessage, Ticks pitEntryCreation,
                        Ticks objReception);
  void (*onTimeout)(StrategyImpl *strategy, const NumberSet *egressId);
  NumberSet *(*lookupNexthop)(StrategyImpl *strategy,
#ifdef WITH_POLICY
    NumberSet * nexthops,
#endif /* WITH_POLICY */
                              const Message *interestMessage);
#ifndef WITH_POLICY
  NumberSet *(*returnNexthops)(StrategyImpl *strategy);
  unsigned (*countNexthops)(StrategyImpl *strategy);
#endif /* ! WITH_POLICY */
  void (*addNexthop)(StrategyImpl *strategy, unsigned connectionId);
  void (*removeNexthop)(StrategyImpl *strategy, unsigned connectionId);
  void (*destroy)(StrategyImpl **strategyPtr);
  hicn_strategy_t (*getStrategy)(StrategyImpl *strategy);
};

#endif  // strategyImpl_h
