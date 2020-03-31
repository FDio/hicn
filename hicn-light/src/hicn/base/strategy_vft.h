/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * \file strategy_vft.h
 * \brief hICN forwarding strategy VFT
 */
#ifndef HICN_STRATEGY_VFT_H
#define HICN_STRATEGY_VFT_H

#include <hicn/base/strategy.h>
#include <hicn/base/nexthops.h>

/**
 * @typedef strategy_ops_t
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
typedef struct {
    const char * name;

    void (*initialize)(strategy_entry_t * entry);

    void (*finalize)(strategy_entry_t * entry);

    nexthops_t * (*lookup_nexthops)(strategy_entry_t * entry, nexthops_t * nexthops,
            const msgbuf_t * msgbuf);

    void (*add_nexthop)(strategy_entry_t * strategy, unsigned nexthop, strategy_nexthop_state_t * state);

    void (*remove_nexthop)(strategy_entry_t * entry, unsigned nexthop, strategy_nexthop_state_t * state);

    void (*on_data)(strategy_entry_t * entry, const nexthops_t * nexthops,
            const msgbuf_t * msgbuf, Ticks pitEntryCreation, Ticks objReception);

    void (*on_timeout)(strategy_entry_t * entry, const nexthops_t * nexthops);

} strategy_ops_t;

extern const strategy_ops_t * const strategy_vft[];

#define DECLARE_STRATEGY(NAME)                                  \
const strategy_ops_t strategy_ ## NAME = {                      \
    .name = #NAME,                                              \
    .initialize = strategy_ ## NAME ## _initialize,             \
    .finalize = strategy_ ## NAME ## _finalize,                 \
    .add_nexthop = strategy_ ## NAME ## _add_nexthop,           \
    .remove_nexthop = strategy_ ## NAME ## _remove_nexthop,     \
    .lookup_nexthops = strategy_ ## NAME ## _lookup_nexthops,   \
    .on_data = strategy_ ## NAME ## _on_data,                   \
    .on_timeout = strategy_ ## NAME ## _on_timeout,             \
}

#endif /* HICN_STRATEGY_VFT_H */
